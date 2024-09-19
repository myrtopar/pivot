## autoexploit
Iwconfig.py exploits the program iwconfig and provides a root shell. Must disable kernel.dmesg_restrict
docker run --rm --privileged -v `pwd`:/host -it ethan42/iwconfig

bof1.py exploits the program bof1 and spawns a /bin/sh
docker run --rm --privileged -v `pwd`:/app -it  vuln-image


issues:<br />
~~1. expecting  a sigsegv signal but not getting it~~ <br />
~~2. although the exploit works just fine, strace does not trace any execve system calls for some reason~~<br />
**_3. problem with generating test cases "AAAA..." number of bytes in the overflow buffer at the time of the crash does not match the expected. Same problem occurs with the byte pattern from pwn-> Why does gdb indicate that eip is at the bytes 137-140 when in practice i have to add 4 additional bytes for the payload to work?_**<br />
4. Is there a way to know where the program gets its input from? => NO<br />
5. How to decide what shellcode is suitable for each exploit? => ??<br />
~~6. What is an indicator that an exploit has been successfully executed? I assume that "0 in rlist" is a sign. Is this sufficient to explicitly state that the shell has started functioning properly?~~<br />
~~7. What if a program is given a payload but it does not produce any output itself? How will I identify the crash? Maybe try strace again.~~
~~8. Must change the gdb commands (breakpoint placement)~~<br />

what to change:
1. find a way to make crash testing faster, it is too slow with `docker exec`
~~2. define a test case generator method (next_test_case)~~
3. define the shellcode somewhere else
4. change the exploit command => WHY?


# MAJOR ISSUE: 
i see a missing pattern in the first process only. <br />
**25165 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_KILLED, si_pid=25198, si_uid=0, si_status=SIGTERM, si_utime=0, si_stime=0} ---**<br />
25218 execve("/bin/sh", ["/bin/sh", "-c", "cat vuln_payload - | ./vuln cat"...], 0x1b69c10 /* 10 vars */) = 0<br />
25219 execve("/usr/bin/cat", ["cat", "vuln_payload", "-"], 0x5886a1e4d358 /* 10 vars */) = 0<br />
25221 execve("/usr/bin/cat", ["cat", "trash"], 0x5886a1e4d378 /* 10 vars */) = 0<br />
25221 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25221, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25222 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b8947038 /* 10 vars */) = 0<br />
25222 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25222, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25223 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b8908038 /* 10 vars */) = 0<br />
25223 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25223, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25224 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b88cb038 /* 10 vars */) = 0<br />
25224 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25224, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25225 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b8892038 /* 10 vars */) = 0<br />
25225 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25225, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25226 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b8861038 /* 10 vars */) = 0<br />
25226 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25226, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25227 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b8840038 /* 10 vars */) = 0<br />
25227 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25227, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25228 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b8810038 /* 10 vars */) = 0<br />
25228 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25228, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25229 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b87d2038 /* 10 vars */) = 0<br />
25229 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25229, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25230 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b8797038 /* 10 vars */) = 0<br />
25230 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25230, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25231 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b8762038 /* 10 vars */) = 0<br />
25231 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25231, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25232 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b8739038 /* 10 vars */) = 0<br />
25232 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25232, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25233 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b8716038 /* 10 vars */) = 0<br />
25233 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25233, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25234 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b86f2038 /* 10 vars */) = 0<br />
25234 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25234, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25235 execve("/usr/bin/cat", ["cat", "trash"], 0x77f7b86ba038 /* 10 vars */) = 0<br />
25235 +++ exited with 0 +++<br />
25220 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=25235, si_uid=0, si_status=0, si_utime=0, si_stime=0} ---<br />
25220 execve("./vuln", ["./vuln", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"..., "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"..., "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"...,<br /> "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"..., "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"..., "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"..., "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"..., <br />"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"..., "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"..., "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"..., "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"..., <br />"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"..., "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"..., "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"..., "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"...], 0x77f7b868b078 /* 10 vars */)<br /> = 0
25220 --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0xffa49804} ---<br />
25220 +++ killed by SIGSEGV (core dumped) +++<br />
25218 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_DUMPED, si_pid=25220, si_uid=0, si_status=SIGSEGV, si_utime=0, si_stime=4} ---<br />
25218 --- SIGTERM {si_signo=SIGTERM, si_code=SI_USER, si_pid=25165, si_uid=0} ---<br />
25218 +++ killed by SIGTERM +++<br />
25165 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_KILLED, si_pid=25218, si_uid=0, si_status=SIGTERM, si_utime=0, si_stime=0} ---<br />
25219 +++ exited with 1 +++<br />

Some logs to showcase what is happening. The program prints that for loop i = 0: pid = 25198 meaning that the first exploit proc is 25198 and for loop i=1: pid = 25218
So if I ignore the first line of the log here, I see that it starts with the second process normally where it spawns some more processess and one of its children, ./vuln, crashes so the parent 25218 receives sigchld with segmentation fault from its child and then gets terminated because I do so in my code. This pattern is exactly the same for all the next loops until the one that succeeds and seems perfectly normal. But I am missing on all the information about the first try meaning the first loop. There is only one line that contains the first exploit process, 25198 and it is from its parent that gets a sigchld because 25198 got terminated with sigterm. I do not see anywhere the process of the crash. Why is that? This messes up the flow of my code because in each try I always look for the line in the log where the exploit process gets a sigchild because of its child crashing with segmentation but only in the first try I dont get it.
**Is it a problem of timing between the actual events of the crash and the strace logs, a race condition or something of that matter?**
###race condition: script editing strace.log vs strace adding logs simultaneously







