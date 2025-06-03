from .utils import *
from .payload_utils import *
from .exploit_utils import *
from .exploration_ulits import *
from .dataclass_utils import *

# @@ --> argv input (inline raw bytes or file path)
# (no @@) --> stdin input
# pivot -i path/to/crash -- /mnt/binaries/ncompress @@
# pivot -i path/to/crash -- /mnt/binaries/iwconfig @@
# pivot -i path/to/crash -- /mnt/binaries/aspell c
# pivot -i path/to/crash -- /mnt/binaries/vuln


def main():

    from pwn import context
    context.log_level='error'

    if len(sys.argv) < 2:
        logging.error("No target binary provided")
        sys.exit(1)

    target_obj = check_args()
    attach_strace()


    reproducer(target_obj)

    crash_mutation = crash_explorer(target_obj)
    # sys.exit(0)

    if crash_mutation == None:
        logging.error("No successful crash input mutation found.")
        cleanup(1)

    target_obj.target_input.content = crash_mutation

    verify_eip_control(target_obj)
    payload_builder(target_obj)

    payload_tester(target_obj)


if __name__ == "__main__":
    main()
