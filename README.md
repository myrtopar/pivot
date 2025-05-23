# Pivot

## Description
This system is designed to exploit binaries with buffer overflow vulnerabilities, ultimately providing shell access. It automates the exploitation process by analyzing the crashing behavior of vulnerable binary executable programs. The script systematically attacks these binaries with crafted inputs, observing how the program crashes and extracting valuable information. This data is then used to develop a precise payload that manipulates vulnerable memory, enabling the execution of arbitrary code. By gaining control over the execution flow, the program successfully spawns a shell, demonstrating how vulnerabilities can be exploited for full system access.

## Install and Build

```sh
git clone https://github.com/myrtopar/pivot.git .
docker pull myrtopar/pivot:latest
docker build -t myrtopar/pivot .
```

## Demo Run

```sh
cd /path/to/cloned/repo
docker run --rm --privileged -v -it myrtopar/pivot:latest


#pivot generates a reproducible exploit
pivot -i {crash_input} {target_bin} {arg_config}
```
**crash_input**: file name of crash input or raw bytes of input <br />
**target_bin**: name of the target binary program <br />
**arg_config**: argument configuration of the vulnerable target binary (e.g {arg1} @@ {arg3} ... where <u>@@</u> is the payload access point) <br />

## System Diagram

```mermaid
graph LR
  Binary --> Reproducer
  Input[Crashing Input] --> Reproducer
  Configuration --> Reproducer
  Reproducer --> Explorer[Crash Explorer]
  Explorer --> Payload[Payload Builder]
  Payload --> Thrower[Payload Tester]
  Thrower --> Thrower
  Explorer --> RootCause[Root Cause Analysis]
  RootCause --> Explorer
  Thrower --> Exploit
```

**Binary**: Target binary to be exploited.<br />
**Crashing input**: when the target binary is executed with this specific input, it will trigger a segmentation fault.<br />
**Configuration**: Information on how the program should be executed (command line arguments needed).<br />
**Reproducer**: Validates that the input causes a memory corruption crash and reproduces the crash.<br />
**Root Cause Analysis**: Confirms that a payload input was provided, capable of reaching the return address.<br />
**Crash explorer**: Analyzes the metadata of a crash that failed to reach the return address and generates a mutation.<br />


## LICENSE

MIT license

## Demo

Produced in [asciinema](https://asciinema.org/).

## Add your target binaries
To use the program on your own vulnerable target binaries, you can add them by modifying the provided Dockerfile. Copy your binary in the `/mnt/binaries` directory.
Make sure to disable NX and stack canary. <br />
`gcc -fno-stack-protector -z execstack -Wl, -z, relro, -z, lazy -o target_bin source.c`


## Tests
```sh
docker run --rm --privileged -v `pwd`/tests:/app/tests -it myrtopar/pivot:latest
pytest tests/
```
<!-- for tests: <br />
docker run --rm --privileged -v `pwd`/src:/app/src -v `pwd`/tests:/app/tests -v `pwd`/crash_inputs:/app/crash_inputs -e PYTHONPATH=/app/src -it myrtopar/autoexploit:latest <br />
python3 -m pytest tests/test_exploit.py::test_exploit <br />




