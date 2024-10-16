from pwn import *
import select
import argparse
import fcntl

log_file_path = 'strace.log'

def drain_fd(fd: int):
    try:
        while True:
            rlist, _, _ = select.select([fd], [], [], 0.2)
            if not rlist:
                break     #drained all trash content
            
            try:
                os.read(fd, 10000)
            except OSError:
                break
    except Exception as e:
        print(f"An error occurred while draining the buffer: {e}")
        cleanup()


def attach_strace():
    main_pid = os.getpid()
    strace_command = f"strace -f -e execve -p {str(main_pid)} -o strace.log"

    #all error logs to devnull to keep stdout clean
    with open(os.devnull, 'w') as devnull:
        subprocess.Popen(
            strace_command, 
            shell=True, 
            stderr=devnull
        )


    while not os.path.isfile('strace.log'):
        time.sleep(0.1)


def truncate_log():
    #seek doesnt work, file fills up with \x00
    with open(log_file_path, 'a+') as log_file:
        fcntl.flock(log_file, fcntl.LOCK_EX)
        try:
            log_file.truncate(0)  #empty log file to reduce load during searches
            log_file.seek(0)
        finally:
            fcntl.flock(log_file, fcntl.LOCK_UN)

def check_target_bin(target):

    # if not os.path.isfile(f'/usr/local/bin/{target}'):
    #     raise argparse.ArgumentTypeError(f"Error: '{target}' does not exist.")
    # if not os.access(f'/mnt/binaries/{target}', os.X_OK):
    #     raise argparse.ArgumentTypeError(f"Error: '{target}' is not executable or permission is denied.")
    
    return target
    

def check_args():

    parser = argparse.ArgumentParser(
        description="a script that exploits a target binary and spawns a shell"
    )

    parser.add_argument(
        "target",
        type=check_target_bin,
        help="The target binary file to execute (must exist in /mnt/binaries and be executable)"
    )

    # parser.add_argument(
    #     "input_mode",
    #     type=int,
    #     choices=[0, 1],
    #     help="Input mode for the target: 0 for stdin (default), 1 for command-line input"
    # )
    args = parser.parse_args()


    return args


def cleanup(exit_code: int):

    os.remove("trash")
    os.remove("payload")
    os.remove("strace.log")
    sys.exit(exit_code)