import select
import fcntl
import logging
import os
import subprocess
import sys
import time
import struct
import glob
import shutil
import argparse
import re
import inspect
import termios
import signal

import pwnlib.args
pwnlib.args.free_form = False   #for argparse compatibility and accepting capitalized arguments
from pwn import process, Corefile, PTY

strace_log_path = "strace.log"

SUCCESS_LEVEL = 35
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")


def success(self, message, *args, **kwargs):
    if self.isEnabledFor(SUCCESS_LEVEL):
        self._log(SUCCESS_LEVEL, message, args, **kwargs)

logging.Logger.success = success

pivot_logger = logging.getLogger("pivot")
pivot_logger.setLevel(logging.DEBUG)


def setup_logging(enable_log: bool, verbose: bool) -> None:

    app_log_path = "pivot.log"

    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"

    class ColorFormatter(logging.Formatter):
        def format(self, record):
            #red color to ERROR level messages, green to custom made success level messages
            if record.levelno == logging.ERROR:
                record.levelname = f"{RED}{record.levelname}{RESET}"
            elif record.levelno == SUCCESS_LEVEL:
                record.levelname = f"{GREEN}{record.levelname}{RESET}"
            return super().format(record)

    #always output error and success messages to console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(SUCCESS_LEVEL)
    console_handler.setFormatter(ColorFormatter("%(asctime)s - %(levelname)s - %(message)s"))
    pivot_logger.addHandler(console_handler)

    if verbose:
        verbose_handler = logging.StreamHandler()
        verbose_handler.setLevel(logging.DEBUG)
        verbose_handler.setFormatter(ColorFormatter("%(asctime)s - %(levelname)s - %(message)s"))
        pivot_logger.addHandler(verbose_handler)

    # File handler (if --log), logs everything
    if enable_log:
        file_handler = logging.FileHandler(app_log_path)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        ))
        pivot_logger.addHandler(file_handler)


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
        pivot_logger.error(f"An error occurred while draining the buffer: {e}")
        cleanup()


def disable_echo(fd):
    attrs = termios.tcgetattr(fd)
    attrs[3] = attrs[3] & ~termios.ECHO  # lflags
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def attach_strace():
    strace_command = f"strace -f -e trace=clone,fork,vfork,execve -p {str(os.getpid())} -o strace.log"

    # all error logs to devnull to keep stdout clean
    with open(os.devnull, "w") as devnull:
        strace_proc = subprocess.Popen(
            strace_command, 
            shell=True,
            stderr=devnull
        )

    while not os.path.isfile(f"strace.log"):
        time.sleep(0.1)

    return strace_proc

def detect_real_crash(parent_proc: int) -> int:
    crash_pattern = re.compile(r"^(\d+)\s+\+\+\+ killed by SIGSEGV \(core dumped\) \+\+\+")
    pid = None
    try:
        with open(f"strace.log", "r") as log_file:
            lines = log_file.readlines()
            for line in lines:
                match = crash_pattern.search(line)
                if match:
                    pid = int(match.group(1))
                    if pid not in range(parent_proc, parent_proc + 5):
                        continue

    except FileNotFoundError:
        pivot_logger.error("Strace log file not found.")
        cleanup(1)

    return pid


def truncate_log():
    # seek doesnt work, file fills up with \x00
    with open(strace_log_path, "a+") as log_file:
        fcntl.flock(log_file, fcntl.LOCK_EX)
        try:
            log_file.truncate(0)  # empty log file to reduce load during searches
            log_file.seek(0)
        finally:
            fcntl.flock(log_file, fcntl.LOCK_UN)


def build_command(target) -> str:

    command_str = ''
    if target.target_input.type == 'stdin':
        # command_str = 'cat mutation - | '
        command_str = 'cat mutation | '

    command = [target.path]

    for arg in target.argv:
        if arg == '@@':
            # arg = target.target_input.content
            arg = '`cat mutation`'
        
        command.append(arg)
    
    command_str += " ".join(command)

    return command_str


def valid_stack_addr(reg: int, stack_top: int, stack_bottom: int) -> bool:
    return stack_top <= reg <= stack_bottom


def cleanup(exit_code: int):

    remove_if_exists('mutation')
    remove_if_exists('strace.log')
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
