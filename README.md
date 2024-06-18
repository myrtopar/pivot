# autoexploit
Iwconfig.py exploits the program iwconfig and provides a root shell. Must disable kernel.dmesg_restrict
docker run --rm --privileged -v `pwd`:/host -it ethan42/iwconfig

bof1.py exploits the program bof1 and spawns a /bin/sh
docker run --rm --privileged -v `pwd`:/app -it  vuln-image

The program vuln takes input from standard input so I must put a hyphen in the command in order to be able to pass additional input when the program gets successfully exploited and a shell spawns. The resulting input is the payload I provide along with an input of the user appended in the end. This forces the user to press enter each time the the program begins to run. I cannot pipe the stdin and stdout in the subprocess because when the program gets exploited, I wont be able to pass more input and see the output of the bash commands.