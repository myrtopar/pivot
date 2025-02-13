from pwn import *
import glob
import argparse
from payload_utils import root_cause_analysis

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

    core_files = glob.glob(f'/core_dumps/core.{arg_config.target}.*')
    if not core_files:
        raise FileNotFoundError("core file not found while initializing the crash exploration. Ensure that the reproducer makes sure the initial input causes a crash.")

    core_path = core_files[-1]
    core = Corefile(core_path)

    cr = critical_registers(core, crash_input)

    #initialize the state of the exploration: no attempted mutations, havent tried overwriting any register values yet
    state = {
        'current_input': crash_input,
        'critical_registers': cr,
        'attempted_mutations': {reg: set() for reg in cr},  #track attempted mutations to avoid repetitions while exploring
        'corefile': core_path
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

        #generating a valid address     -> will replace with a pool of possible addresses
        stack_addr = (core.stack.start + core.stack.stop) // 2
        stack_addr += 4
        valid_addr = struct.pack('<I', stack_addr)

        mutation = state['current_input'].replace(reg_value, valid_addr)

        reached_eip = root_cause_analysis(mutation, arg_config)     #produces new core file (or not if it is a deadend)

        if reached_eip == True:
            return mutation

        elif reached_eip == False:
            #new state for going 1 level lower

            core_files = glob.glob(f'/core_dumps/core.{arg_config.target}.*')
            core_files = sorted(core_files, key=lambda f: int(f.split('.')[-1]), reverse=True)  #sort core files in reverse order based on pid to find the last one 

            if not core_files:
                raise FileNotFoundError('core file not found during exploration')
            core_path = core_files[0]

            cr = critical_registers(Corefile(core_path), mutation)

            n_state = {
                'current_input': mutation,
                'critical_registers': cr,
                'attempted_mutations': {reg: set() for reg in cr},  #track attempted mutations to avoid repetitions while exploring
                'corefile': core_path
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