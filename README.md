## autoexploit 💖
Iwconfig.py exploits the program iwconfig and provides a root shell. Must disable kernel.dmesg_restrict
docker run --rm --privileged -v `pwd`:/host -it ethan42/iwconfig

bof1.py exploits the program bof1 and spawns a /bin/sh
docker run --rm --privileged -v `pwd`:/app -it  vuln-image

When the exploit is successful and the process spawns a shell, the shell closes only with Ctrl-D (EOF) due to the use of interactive(), and 'exit' doesn't work.

issues:<br />
**_problem with generating test cases "AAAA..." number of bytes in the overflow buffer at the time of the crash does not match the expected. Same problem occurs with the byte pattern from pwntools -> Why does gdb indicate that eip is at the bytes 137-140 when in practice i have to add 4 additional bytes for the payload to work?_**<br />
Is there a way to know where the program gets its input from? => NO<br />
How to decide what shellcode is suitable for each exploit? => ??<br />

to do:<br />
1. figure out what is going on with the ebp/eip issue in the payload<br />
2. fix the log truncating issue<br />
3. add iwconfig in the container<br />
4. create separate handling for stdin and separate for argument inputs<br />
5. create test that _i guess_ will look for an execve??? <br />
6. make a workflow with that test<br />








