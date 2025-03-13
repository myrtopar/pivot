from pwn import *
import glob
from payload_utils import root_cause_analysis
from utils import *
from exploit_utils import ENV_VARS

priority = ['eip', 'ebp', 'esp', 'eax', 'ebx', 'ecx', 'edx']

"""
The crashing input is mutated iteratively to maximize control over EIP.
Some mutations fix invalid memory dereferences to allow further execution.
Some mutations lead to dead ends (program doesn't crash or crashes incorrectly).
The goal is to backtrack when a dead-end is reached, exploring alternative mutations.

find a register value in the input, replace it with an address that hopefully won't crash the program, and try again. However, 
this may not explore all possible paths, because the range of the address pool the explorer tries for each value that makes a 
program crash on a specific register is limited.
"""

def crash_explorer(target: Target):
    """
    Extracts information from the core dump from the previous crash and mutates the crashing input, 
    returns the mutated input to the root_cause_analysis for further crash testing.
    """


    crash_input = target.target_input.content
    if(root_cause_analysis(target, crash_input) == True):
        # no need for program input exploration - the original crashing input already hits eip
        return target.target_input.content

    core_files = glob.glob(f'/core_dumps/core.{target.name}.*')
    if not core_files:
        raise FileNotFoundError('core file not found while initializing the crash exploration. Ensure that the reproducer actually reproduces the initial crash.')

    core_path = core_files[-1]

    regs_pr = sorted(
        critical_registers(core_path, crash_input),
        key=lambda x: (priority.index(x) if x in priority else len(priority), x)
    )

    #initialize the state of the exploration: no attempted mutations, havent tried overwriting any register values yet
    state = {
        'current_input': crash_input,
        'critical_registers': regs_pr,
        'attempted_mutations': {reg: set() for reg in regs_pr},  #track attempted mutations to avoid repetitions while exploring
        'corefile': core_path,
        'address_pool': generate_address_pool(core_path, target, crash_input),
        'level': 0
    }

    return iter_exploration(target, state)


def iter_exploration(target: Target, state: dict):

    #probably here i will follow a different approach for possible mutations. Currently a dead end
    if not state['critical_registers']:
        return None

    core = Corefile(state['corefile'])

    #in each iteration of exploring, a previous input mutation may have caused other new registers to crash with input values. Must add them in again !!

    for reg in state['critical_registers']:
        reg_value = core.registers[reg].to_bytes(4, byteorder='little')
        # print(f'picked reg {reg} with value {reg_value}')

        for new_addr in state['address_pool']:

            #try out all candidate addresses when fixing a register value

            mutation = state['current_input'].replace(reg_value, new_addr)

            reached_eip = root_cause_analysis(target, mutation)     #tries out the mutated input and produces new core file (or not if it is a deadend)

            if reached_eip == True:
                return mutation

            elif reached_eip == False:
                #new state for going 1 level lower in dfs search

                core_files = glob.glob(f'/core_dumps/core.{target.name}.*')
                core_files = sorted(core_files, key=lambda f: int(f.split('.')[-1]), reverse=True)  #sort core files in reverse order based on pid to find the last one 

                if not core_files:
                    raise FileNotFoundError('core file not found during exploration')
                core_path = core_files[0]


                regs_pr = sorted(
                    critical_registers(core_path, mutation),
                    key=lambda x: (priority.index(x) if x in priority else len(priority), x)
                )
                n_level = state['level']+1
                n_state = {
                    'current_input': mutation,
                    'critical_registers': regs_pr,
                    'attempted_mutations': {reg: set() for reg in regs_pr},  #track attempted mutations to avoid repetitions while exploring
                    'corefile': core_path,
                    'address_pool': state['address_pool'],
                    'level': n_level
                }            
                result = iter_exploration(target, n_state)

                if result is not None:
                    return result

            elif reached_eip == None:
                # print('this mutation caused a dead end. The program ended up not crashing at all. Backtracking ...')
                continue

    
    return None


def critical_registers(core_path: str, crash_input: bytes) -> list:

    core = Corefile(core_path)
    critical_regs = []
    for reg in core.registers:
        reg_bytes = core.registers[reg].to_bytes(4, byteorder='little')
        if reg_bytes in crash_input and not valid_stack_addr(core.registers[reg], core.stack.start, core.stack.stop):
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


def generate_address_pool(core_path: str, target: Target, input: bytes) -> list:
    address_pool = []

    core = Corefile(core_path)
    stack_top = core.stack.start
    stack_bottom = core.stack.stop

    esp = core.registers['esp']
    # envvar_len = sum((len(k) + 1) + (len(v) + 1) for k, v in ENV_VARS.items())

    if not valid_stack_addr(esp, stack_top, stack_bottom):

        #if esp is corrupted, we can try ebp instead and create a range around the ebp value
        ebp = core.registers['ebp']

        if not valid_stack_addr(ebp, stack_top, stack_bottom):

            # #if both esp and ebp are corrupted, the addresses cannot be generated based on registers (i guess??), so the range is from the stack base up to the beginning of the point where the env variables are (the range is huge, this must shrink somehow)
            # for addr in range(core.stack.start, core.envp_address, 4):
            #     address_pool.append(struct.pack('<I', addr))

            #another kinda dumb way to generate a range of addresses
            extracted_esp = corrupted_registers(target, input)
            if extracted_esp == 0 or not valid_stack_addr(extracted_esp, stack_top, stack_bottom):
                logging.error('Extracting esp value failed - gdb scripting unsuccessful')

            for i in range(256):
                address_pool.append(struct.pack('<I', (extracted_esp + i * 4)))

        
        else:
            #must change 256. How many addresses in the stack should this pool contain?
            for i in range(256):
                address_pool.append(struct.pack('<I', ebp - i * 4))
                address_pool.append(struct.pack('<I', ebp + i * 4))

    else:
        #must change 256. How many addresses in the stack should this pool contain?
        for i in range(256):
            address_pool.append(struct.pack('<I', (esp + i * 4)))
        

    return address_pool


def valid_stack_addr(reg: int, stack_top: int, stack_bottom: int) -> bool:
    return stack_top <= reg <= stack_bottom


def corrupted_registers(target: Target, input: bytes) -> int:
    """
    Monitors the program with a gdb script and extracts the last value of esp before corruption. 
    By doing so, we get an address that shows roughly where the stack frame of the vulnerable function was located within the stack.
    With this address we can generate a set of neighbor addresses (maybe within that frame or the ones above it) that may be suitable for making the exploit succeed.

    !! The following process is useful only if the registers at the time of the crash are all corrupted and do not reveal anything about the location of the stack frames
    within the stack. The reason we do this is because the stack is 2MB and we cannot try all addresses from the bottom to the top !!
    """
    esp_monitor_gdb(target, input)

    if not os.path.exists('esp.log'):
        return 0
    
    with open('esp.log', 'r') as file:
        if len(file.readlines()) < 20:
            return 0

    
    return extract_esp(input)

def esp_monitor_gdb(target: Target, input: bytes)-> None:

    """
    Produces a gdb log file containing all esp values until esp corruption.
    """
    with open('mutation', 'wb') as mutation:
        mutation.write(input)

    command = build_command(target)
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
        ['gdb', '-q', '-x', 'esp_monitor.gdb', target.path],
        stdin=subprocess.PIPE, 
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    gdb.communicate(input=b'quit\n')


    remove_if_exists('mutation')
    remove_if_exists('esp_monitor.gdb')

    return


def extract_esp(input: bytes) -> int:

    extracted_esp = 0

    #read the last 30 lines of the log file in case of unwanted messages in the end
    with open('esp.log', 'r') as f:
        lines = [line.strip() for line in f.readlines()]

    for i in range(len(lines) - 1, max(len(lines) - 30, -1), -1):
        if lines[i].startswith("0x"):
            esp_value = struct.pack("<I", int(lines[i], 16))

            if esp_value in input and i > 0:
                #found the corrupted esp, the last valid value is right before this value
                extracted_esp = int(lines[i-1], 16)
                break

    remove_if_exists('esp.log')

    return extracted_esp