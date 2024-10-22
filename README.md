## autoexploit 💖

autoexploit.py exploits the target binaries and spawns a /bin/sh<br />
docker run --rm --privileged -v `pwd`/src:/app/src -it myrtopar/autoexploit:latest <br />
python3 src/autoexploit.py {target_bin} <br />

for tests: <br />
docker run --rm --privileged -v `pwd`/src:/app/src -v `pwd`/tests:/app/tests -e PYTHONPATH=/app/src -it myrtopar/autoexploit:latest <br />
python3 -m pytest tests/test_exploit.py::test_exploit <br />

for target binaries with extra arguments: <br />
python3 src/autoexploit.py {target_bin} {arg1} {arg1_pos} <br />

for some reason ncompress also works without arguments => forgot to add the extra arguments to the gdb prompt<br />

e.g <br />
ncompress -c {arg1}<br />
python3 src/autoexploit.py ncompress -c 1<br />



When the exploit is successful and the process spawns a shell, the shell closes only with Ctrl-D (EOF) due to the use of interactive(), and 'exit' doesn't work.
Target binaries go to: /mnt/binaries (included in $PATH)

issues:<br />
Is there a way to know where the program gets its input from? => Maybe? using llms on this specific matter or maybe with strace to look for read()<br />
How to decide what shellcode is suitable for each exploit? => ??<br />

to do:<br />
- fix the log truncating issue<br />
- <del>create test that _i guess_ will look for an execve??? </del><br />
- <del>pack the binaries in an image, upload it in dockerhub, make it public and pull the image from dockerhub in the test workflow</del><br />
- <del>fix the path bug</del><br />
- fix gdb vuln offset bug <br />
- fix interactive command echo bug<br />
- <del>allow arguments for custom cli args (e.g ncompress -c agr1), edit the exploit command for versatile attacks</del><br />
- create more complex testing that targets binaries with more complex buffer overflow attacks (aspell word list compress)<br />
- install poetry, add dependencies<br />
- <del>add structure to the repo</del></br>


Filling up the stack with 2MB of enviroment variables instead of command line arguments => more versatile, works much quicker (idk why) and keeps the arguments available for passing payloads<br />
When passing payload from the arguments, the length of the nopsled must be limited to 130.000 bytes. This reduces the chances of target_ra landing on the nopsled due to the decrease in the nopsled length from 200k to 130k. By providing the payload through stdin, I don't have any limitations on the length of the command line arguments.<br />
Pwntools interactive suddenly started echoing back the command before displaying the results. Idk why, didn't even try to find out.


###tests:
test1: check the correctness of the payload: Is the offset of the ret addr correct? Do I check this manually with gdb?
should I test each method separately? Create mock scenarios for each one of them? And if I do should I add these to the workflow or not? The workflow will look for an execve on every target binary? 