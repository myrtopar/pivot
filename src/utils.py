from pwn import *
from dataclass_utils import Target, TargetInput
import select
import argparse
import fcntl

log_file_path = "strace.log"

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

RESET = "\033[0m"
RED = "\033[31m"


class ColorFormatter(logging.Formatter):
    def format(self, record):
        # Apply red color to ERROR level messages
        if record.levelno == logging.ERROR:
            record.levelname = f"{RED}{record.levelname}{RESET}"
        return super().format(record)


file_handler = logging.FileHandler("app.log")
file_handler.setLevel(logging.INFO)  # Log INFO, WARNING, ERROR, CRITICAL
file_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)  # Log ERROR and CRITICAL only
formatter = ColorFormatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def drain_fd(fd: int):
    try:
        while True:
            rlist, _, _ = select.select([fd], [], [], 0.2)
            if not rlist:
                break  # drained all trash content

            try:
                os.read(fd, 10000)
            except OSError:
                break
    except Exception as e:
        logging.error(f"An error occurred while draining the buffer: {e}")
        cleanup()


def attach_strace():
    main_pid = os.getpid()
    strace_command = f"strace -f -e execve -p {str(main_pid)} -o strace.log"

    # all error logs to devnull to keep stdout clean
    with open(os.devnull, "w") as devnull:
        subprocess.Popen(strace_command, shell=True, stderr=devnull)

    while not os.path.isfile("strace.log"):
        time.sleep(0.1)


def truncate_log():
    # seek doesnt work, file fills up with \x00
    with open(log_file_path, "a+") as log_file:
        fcntl.flock(log_file, fcntl.LOCK_EX)
        try:
            log_file.truncate(0)  # empty log file to reduce load during searches
            log_file.seek(0)
        finally:
            fcntl.flock(log_file, fcntl.LOCK_UN)


def check_target_bin(target):

    target_path = f"/mnt/binaries/{target}"

    if not os.path.isfile(target_path):
        logging.error(f"Program {target} does not exist.")
        sys.exit(1)

    readelf_cmd = f"readelf -h {target_path} | grep 'Class'"

    readelf_proc = subprocess.Popen(
        readelf_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )

    output, _ = readelf_proc.communicate()

    if "ELF32" not in output.decode("utf-8"):
        logging.error("64-bit binaries are not supported by the program.")
        sys.exit(1)

    return


def build_command(target: Target):
    command_str = ''
    if target.target_input.type == 'stdin':
        command_str = 'cat mutation | '

    command = [target.path]

    for arg in target.argv:
        if arg == '@@':
            # arg = target.target_input.content
            arg = '`cat mutation`'
        
        command.append(arg)
    
    command_str += " ".join(command)

    return command_str


def cleanup(exit_code: int):

    # os.remove('payload')
    os.remove("strace.log")
    sys.exit(exit_code)


def remove_if_exists(path: str):
    if os.path.exists(path):
        os.unlink(path)


def interactive_gdb(target: str, corepath: str, env_vars: dict) -> None:

    if corepath is not None:
        gdb_proc = process(
            ["gdb", "--quiet", target, corepath],
            env={**os.environ, **env_vars},
            raw=True,
        )
        gdb_proc.interactive()
    else:
        gdb_proc = process(
            ["gdb", "--quiet", target], env={**os.environ, **env_vars}, raw=True
        )
        gdb_proc.interactive()
