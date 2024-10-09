## autoexploit 💖
Iwconfig.py exploits the program iwconfig and provides a root shell. Must disable kernel.dmesg_restrict
docker run --rm --privileged -v `pwd`:/host -it ethan42/iwconfig

bof1.py exploits the program bof1 and spawns a /bin/sh<br />
docker run --rm --privileged -v `pwd`/auto_bof.py:/app/auto_bof.py -it autoexploit


When the exploit is successful and the process spawns a shell, the shell closes only with Ctrl-D (EOF) due to the use of interactive(), and 'exit' doesn't work.
Target binaries go to: /usr/local/bin

issues:<br />
Is there a way to know where the program gets its input from? => NO<br />
How to decide what shellcode is suitable for each exploit? => ??<br />

to do:<br />
1. figure out what is going on with the ebp/eip issue in the payload<br />
2. fix the log truncating issue<br />
3. create separate handling for stdin and separate for argument inputs<br />
4. create test that _i guess_ will look for an execve??? <br />
5. make a workflow with that test<br />


Filling up the stack with 2MB of enviroment variables instead of command line arguments => more versatile, works much quicker (idk why) and keeps the arguments available<br />
for passing payloads
