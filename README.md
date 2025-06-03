# Pivot

## Description
This system is designed to exploit binaries with buffer overflow vulnerabilities, ultimately providing shell access. It automates the exploitation process by analyzing the crashing behavior of vulnerable binary executable programs. The script systematically tests such binaries with crafted inputs, observing how each program crashes and extracting valuable information. This data is then used to develop a precise payload that manipulates vulnerable memory, enabling the execution of arbitrary code. After gaining control over the execution flow and therefore proving the exploitability of the target, Pivot successfully generates a reproducible exploit script which spawns a shell, demonstrating how vulnerabilities can be exploited for full system access.

## Installation & Build

Option 1 – Pull prebuilt image:
```sh
docker pull ghcr.io/myrtopar/pivot:0.1
```

Option 2 – Clone and build locally:
```sh
git clone https://github.com/myrtopar/pivot.git
cd pivot
docker build -t pivot .
```

## Pivot CLI

### Run in Docker

```sh
docker run --rm --privileged -it ghcr.io/myrtopar/pivot:0.1
```

### Usage
```sh
#pivot generates a reproducible exploit script
pivot --input <crash_input> --target <target_bin> [args...] [--env KEY=VALUE ...] [--log] [--verbose]

```
* **-i**,**--input**: File name of crash input or raw bytes of input
* **-t**,**--target**: Name of the target binary program
* **args**: CLI args for the target binary (use `@@` as payload placeholder)
* **-l**,**--log** (optional): Enables detailed logging to a file inside the container.
* **-v**,**--verbose** (optional): Prints detailed output to the console during execution.
* **-e**,**--env** (optional): 	Environment variables passed to the target (can include `@@` in value for payload placeholder)

### Example
```sh
pivot -i ./crashes/input1 -t ./bin/target ARG1 ARG2 @@ --env FOO=BAR -v -l
```

### Help
```sh
pivot --help
```
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

* **Binary**: Target binary to be exploited.
* **Crashing input**: when the target binary is executed with this specific input, it will trigger a segmentation fault.
* **Configuration**: Information on how the program should be executed (command line arguments needed).
* **Reproducer**: Validates that the input causes a memory corruption crash and reproduces the crash.
* **Root Cause Analysis**: Confirms that a crashing input was provided, capable of tainting the EIP register.
* **Crash explorer**: Analyzes the metadata of a crash that failed to taint the EIP register and generates a mutation.
* **Payload Builder**: Crafts a fully functioning payload based on a previous successful crashing input.
* **Payload Tester**: Attempts exploitation (repeatedly if the binary is PIE), and upon success, generates a script that reproduces the exploit on the target.


## Adding Your Own Targets
To test your own vulnerable binaries:
1. Copy them into `/mnt/binaries/` in the Docker container. All binaries in this directory are automatically added to the `PATH`.
2. Ensure they are compiled for 32-bit and with NX and stack canary disabled. <br />
`gcc -fno-stack-protector -z execstack -m32 -o target_bin target_source.c`
3. Generate a crashing input that reliably triggers a buffer overflow in your binary.
We recommend using the pwn.cyclic module from Pwntools to craft such inputs.
Note: Pivot does not include fuzzing techniques — it requires a known crashing input to begin analysis.

A recorded demo is provided below to illustrate this process.

## Tests
```sh
docker run --rm --privileged -v `pwd`/tests:/app/tests -it ghcr.io/myrtopar/pivot:0.1
pytest tests/
```
## LICENSE
MIT license

## Demo
Produced in [asciinema](https://asciinema.org/)
[![asciicast](https://asciinema.org/a/uKYdPCjG9pioePk4MwUCxfMLs.svg)](https://asciinema.org/a/uKYdPCjG9pioePk4MwUCxfMLs)