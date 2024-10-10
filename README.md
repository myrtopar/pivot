## autoexploit 💖
Iwconfig.py exploits the program iwconfig and provides a root shell. Must disable kernel.dmesg_restrict
docker run --rm --privileged -v `pwd`:/host -it ethan42/iwconfig

bof1.py exploits the program bof1 and spawns a /bin/sh<br />
docker run --rm --privileged -v `pwd`/auto_bof.py:/app/auto_bof.py -v `pwd`/binaries:/mnt/binaries -it autoexploit

When the exploit is successful and the process spawns a shell, the shell closes only with Ctrl-D (EOF) due to the use of interactive(), and 'exit' doesn't work.
Target binaries go to: /usr/local/bin

issues:<br />
Is there a way to know where the program gets its input from? => Maybe? using llms on this specific matter or maybe with strace to look for read()<br />
How to decide what shellcode is suitable for each exploit? => ??<br />

to do:<br />
2. fix the log truncating issue<br />
4. create test that _i guess_ will look for an execve??? <br />
5. make a workflow with that test<br />


Filling up the stack with 2MB of enviroment variables instead of command line arguments => more versatile, works much quicker (idk why) and keeps the arguments available for passing payloads<br />
When passing payload from the arguments, the length of the nopsled must be limited to 130.000 bytes. This reduces the chances of target_ra landing on the nopsled due to the decrease in the nopsled length from 200k to 130k. By providing the payload through stdin, I don't have any limitations on the length of the command line arguments.<br />
Pwntools interactive suddenly started echoing back the command before displaying the results. Idk why, didn't even try to find out.
