from pwn import *
import glob
import argparse
from payload_utils import root_cause_analysis
from utils import interactive_gdb, build_command, remove_if_exists
from exploit_utils import ENV_VARS


"""
The crashing input is mutated iteratively to maximize control over EIP.
Some mutations mute crashes (fix invalid memory dereferences) to allow further execution.
Some mutations lead to dead ends (program doesn't crash or crashes incorrectly).
The goal is to backtrack when a dead-end is reached, exploring alternative mutations.

find a register value in the input, replace it with a stack address, and try again. However, 
this may not explore all possible paths. For example, there might be multiple registers causing crashes, 
and replacing one might not address another. Or the order in which registers are handled matters.
"""

def crash_explorer2(crash_input: bytes, arg_config: argparse.Namespace):
    """
    Extracts information from the core dump from the previous crash and mutates the crashing input, 
    returns the mutated input to the root_cause_analysis for further crash testing.
    """

    #maybe prioritize the critical registers with a lambda based on this priority order???
    # priority = ['eip', 'ebp', 'esp', 'eax', 'ebx', 'ecx', 'edx']

    if(root_cause_analysis(crash_input, arg_config) == True):
        # no need for program input exploration - the original crashing input already hits eip
        return crash_input

    core_files = glob.glob(f'/core_dumps/core.{arg_config.target}.*')
    if not core_files:
        raise FileNotFoundError('core file not found while initializing the crash exploration. Ensure that the reproducer makes sure the initial input causes a crash.')

    core_path = core_files[-1]
    core = Corefile(core_path)

    # interactive_gdb(arg_config.target, core_path, ENV_VARS)

    cr = critical_registers(core, crash_input)


    #initialize the state of the exploration: no attempted mutations, havent tried overwriting any register values yet
    state = {
        'current_input': crash_input,
        'critical_registers': cr,
        'attempted_mutations': {reg: set() for reg in cr},  #track attempted mutations to avoid repetitions while exploring
        'corefile': core_path,
        'address_pool': generate_address_pool(core_path, arg_config, crash_input)
    }

    return iter_exploration(crash_input, arg_config, state)


def iter_exploration(crash_input: bytes, arg_config: argparse.Namespace, state: dict):

    #probably here i will follow a different approach for possible mutations. Currently a dead end
    if not state['critical_registers']:
        return None
    
    core = Corefile(state['corefile'])

    #in each iteration of exploring, a previous input mutation may have caused other new registers to crash with input values. Must add them in again !!

    for reg in state['critical_registers']:
        reg_value = core.registers[reg].to_bytes(4, byteorder='little')
        print(f'picked reg {reg} with value {reg_value}')

        #generating a valid address     -> will replace with a pool of candidate addresses
        # stack_addr = (core.stack.start + core.stack.stop) // 2
        # stack_addr += 4
        # valid_addr = struct.pack('<I', stack_addr)

        for new_addr in state['address_pool']:

            #try out all candidate addresses when fixing a register value

            mutation = state['current_input'].replace(reg_value, new_addr)
            print(f'will replace this value with new stack address {new_addr}')

            reached_eip = root_cause_analysis(mutation, arg_config)     #tries out the mutated input and produces new core file (or not if it is a deadend)
            print(f'reached eip: {reached_eip}')

            if reached_eip == True:
                return mutation

            elif reached_eip == False:
                #new state for going 1 level lower in dfs search

                core_files = glob.glob(f'/core_dumps/core.{arg_config.target}.*')
                core_files = sorted(core_files, key=lambda f: int(f.split('.')[-1]), reverse=True)  #sort core files in reverse order based on pid to find the last one 

                if not core_files:
                    raise FileNotFoundError('core file not found during exploration')
                core_path = core_files[0]

                # interactive_gdb(arg_config.target, core_path, ENV_VARS)
                # backtrace(arg_config.target, core_path)

                cr = critical_registers(Corefile(core_path), mutation)

                n_state = {
                    'current_input': mutation,
                    'critical_registers': cr,
                    'attempted_mutations': {reg: set() for reg in cr},  #track attempted mutations to avoid repetitions while exploring
                    'corefile': core_path,
                    'address_pool': generate_address_pool(core_path, arg_config, mutation)
                }            
                iter_exploration(mutation, arg_config, n_state)

            elif reached_eip == None:
                print('this mutation caused a dead end. The program ended up not crashing at all. Backtracking ...')

                return None



def critical_registers(core: Corefile, crash_input: bytes) -> list:

    critical_regs = []
    for reg in core.registers:
        reg_value = core.registers[reg].to_bytes(4, byteorder='little')
        if reg_value in crash_input:
            critical_regs.append(reg)
    
    return critical_regs

def backtrace(target: str, core_path: str):

    cmd = ['gdb', '-batch', '-ex', 'bt', f'./{target}', core_path]
    core_proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    output, _ = core_proc.communicate()
    print(f'output of backtrace: {output}')
    return

def generate_address_pool(core_path: str, arg_config: argparse.Namespace, input: bytes) -> list:
    address_pool = []

    core = Corefile(core_path)
    stack_top = core.stack.start
    stack_bottom = core.stack.stop
    print(f'stack base: {hex(core.stack.start)}, top: {(core.stack.stop)}')

    esp = core.registers['esp']
    # envvar_len = sum((len(k) + 1) + (len(v) + 1) for k, v in ENV_VARS.items())

    if not valid_stack_addr(esp, stack_top, stack_bottom):

        #if esp is corrupted, we can try ebp instead and create a range around the ebp value
        ebp = core.registers['ebp']
        print(f'esp is invalid, ebp: {hex(ebp)}')

        if not valid_stack_addr(ebp, stack_top, stack_bottom):

            # #if both esp and ebp are corrupted, the addresses cannot be generated based on registers (i guess??), so the range is from the stack base up to the beginning of the point where the env variables are (the range is huge, this must shrink somehow)
            # for addr in range(core.stack.start, core.envp_address, 4):
            #     address_pool.append(struct.pack('<I', addr))
            extracted_esp = corrupted_registers(arg_config, input)
            if extracted_esp == 0:
                logging.error('Extracting esp value failed - gdb scripting unsuccessful')
                
            sys.exit(1)

        else:
            #must change 256. How many addresses in the stack should this pool contain?
            for i in range(256):
                address_pool.append(struct.pack('<I', ebp - i * 4))
                address_pool.append(struct.pack('<I', ebp + i * 4))

    else:
        #must change 256. How many addresses in the stack should this pool contain?
        for i in range(256):
            address_pool.append(struct.pack('<I', (esp + i * 4)))
        


    print(f'address pool: {len(address_pool)}')

    return address_pool


def valid_stack_addr(reg: int, stack_top: int, stack_bottom: int) -> bool:
    return stack_top <= reg <= stack_bottom


def corrupted_registers(arg_config: argparse.Namespace, input: bytes) -> int:
    """
    Monitors the program with a gdb script and extracts the last value of esp before corruption. 
    By doing so, we get an address that shows roughly where the stack frame of the vulnerable function was located within the stack.
    With this address we can generate a set of neighbor addresses (maybe within that frame or the ones above it) that may be suitable for making the exploit succeed.

    !! The following process is useful only if the registers at the time of the crash are all corrupted and do not reveal anything about the location of the stack frames
    within the stack. The reason we do this is because the stack is 2MB and we cannot try all addresses from the top to the bottom !!
    """
    esp_monitor_gdb(arg_config, input)

    if not os.path.exists('esp.log'):
        return 0
    return

def esp_monitor_gdb(arg_config: argparse.Namespace, input: bytes):

    """
    Produces a gdb log file containing all esp values until esp corruption.
    """
    with open('mutation', 'wb') as f:
        f.write(input)

    command = build_command(arg_config, input)
    command.pop(0)      #remove the name of the program

    cmd = ''
    for arg in command:
        if type(arg) == bytes:          
            cmd += f' `cat mutation`'
        else:
            cmd += f' {arg}'


    gdb_script = f"""\
set pagination off
set logging file esp.log
set logging enabled on
set logging redirect on

b main

catch signal SIGSEGV
commands
  printf "Received SIGSEGV, bye\\n"
  quit
end

r{cmd} < mutation

set $prev_esp = $esp 

while 1
    set logging enabled off
    si
    set logging enabled on 

    if $esp != $prev_esp
        printf "%p\\n", $esp
        set $prev_esp = $esp
    end
end
"""
    with open('esp_monitor.gdb', 'w') as script:
        script.write(gdb_script)

    gdb = subprocess.Popen(
        ['gdb', '-q', '-x', 'esp_monitor.gdb', arg_config.target],
        stdin=subprocess.PIPE, 
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    gdb.communicate(input=b'quit\n')


    remove_if_exists('mutation')
    remove_if_exists('esp_monitor.gdb')

    return