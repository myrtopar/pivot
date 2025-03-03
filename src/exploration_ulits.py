from pwn import *
import glob
import argparse
from payload_utils import root_cause_analysis
from utils import interactive_gdb
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
        'address_pool': generate_address_pool(core_path)
    }

    interactive_gdb(arg_config.target, core_path, ENV_VARS)
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
                    'address_pool': generate_address_pool(core_path)
                }            
                iter_exploration(crash_input, arg_config, n_state)

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

def generate_address_pool(core_path: str) -> list:
    address_pool = []

    core = Corefile(core_path)

    # stack_addr = (core.stack.start + core.stack.stop) // 2
    # stack_addr += 4
    # stack_addr = struct.pack('<I', stack_addr)


    esp = core.registers['esp']

    esp_hex = struct.pack('<I', esp)
    print(f'esp: {esp_hex}')
    stack_base = struct.pack('<I', core.stack.start)
    stack_top = struct.pack('<I', core.stack.stop)
    print(f'stack base: {stack_base} and top: {stack_top}')
    # envvar_len = sum((len(k) + 1) + (len(v) + 1) for k, v in ENV_VARS.items())


    # for stack_addr in range(range_start, range_stop, 4):
    #     address_pool.add(struct.pack('<I', stack_addr))

    for i in range(256):
        address_pool.append(struct.pack('<I', (esp + i * 4)))

    print(f'address pool: {address_pool}')

    # print(f'address pool: {address_pool}')
    # interactive_gdb('july', core_path, ENV_VARS)

    return address_pool