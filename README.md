## autoexploit
Iwconfig.py exploits the program iwconfig and provides a root shell. Must disable kernel.dmesg_restrict
docker run --rm --privileged -v `pwd`:/host -it ethan42/iwconfig

bof1.py exploits the program bof1 and spawns a /bin/sh
docker run --rm --privileged -v `pwd`:/app -it  vuln-image

The program vuln takes input from standard input so I must put a hyphen in the command in order to be able to pass additional input when the program gets successfully exploited and a shell spawns. The resulting input is the payload I provide along with an input of the user appended in the end. This forces the user to press enter each time the the program begins to run. I cannot pipe the stdin and stdout in the subprocess because when the program gets exploited, I wont be able to pass more input and see the output of the bash commands.

issues:
1. expecting  a sigsegv signal but not getting it
2. although the exploit works just fine, strace does not trace any execve system calls for some reason
3. problem with generating test cases "AAAA..." number of bytes in the overflow buffer at the time of the crash does not match the expected.
4. Is there a way to know where the program gets its input from?
5. How to decide what shellcode is suitable for each exploit?
**6. What is an indicator that an exploit has been successfully executed? I assume that "0 in rlist" is a sign. Is this sufficient to explicitly state that the shell has started functioning properly?**

# MEGA ISSUE: 
how to connect the slave side of the pty to the vuln command during the brute force attack? 
Docker exec prevents me from having direct access to vuln input and output file descriptors ect
Also docker exec has a very slow performance in repetitive procedures like in test case crashing or brute force bof attacking!!!


what to change:
1. find a way to make crash testing faster, it is too slow with `docker exec`
2. define a test case generator method (next_test_case)
3. define the shellcode somewhere else
4. change the exploit command


