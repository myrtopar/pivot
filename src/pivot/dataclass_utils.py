from dataclasses import dataclass, field
from typing import List, Dict, Optional
from .utils import *

@dataclass
class TargetInput:
    type: str
    content: bytes
    file_path: Optional[str] = None


@dataclass
class Target:
    name: str
    path: str
    timeout: int
    target_input: TargetInput
    env: Dict[str, str] = field(default_factory=dict)
    argv: List[str] = field(default_factory=list)


class CrashingInputAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if os.path.isfile(values):
            with open(values, "rb") as f:
                content = f.read()
        else:
            try:
                content = values.encode("utf-8")
            except Exception as e:
                parser.error(f"Invalid inline crashing input: {e}")
        setattr(namespace, self.dest, content)

class ValidateTargetAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) == 0:
            parser.error("No target binary declared.")

        check_target_bin(values[0])  
        setattr(namespace, self.dest, values)

class EnvVarAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        env_vars = {}
        for val in values:
            if '=' not in val:
                parser.error(f"Invalid environment variable format: '{val}' (expected KEY=VALUE)")
            key, value = val.split('=', 1)
            if not key or not value:
                parser.error("Environment variables must be provided in KEY=VALUE format.")
            env_vars[key] = value
        setattr(namespace, self.dest, env_vars)


def check_args() -> Target:

    parser = argparse.ArgumentParser(
        description="a script that exploits a target binary and spawns a shell"
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to crash input file",
        action=CrashingInputAction,
    )


    parser.add_argument(
        "-l",
        "--log",
        action="store_true",
        help="Enable logging to file (default: app.log)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print all logs (DEBUG, INFO, etc.) to the console",
    )

    parser.add_argument(
        "-e",
        "--env",
        nargs="+",
        required=False,
        help="Environment variables needed for the target binary",
        action=EnvVarAction,
    )

    parser.add_argument(
        "-t",
        "--target",
        nargs="+",
        required=True,
        action=ValidateTargetAction,
        help="Target binary followed by its required arguments and/or argument placeholders (@@)",
    )

    args = parser.parse_args()
    setup_logging(args.log, args.verbose)

    input = TargetInput(
        type=detect_input_type(args),
        content=args.input,
    )

    target_name = args.target[0]
    target_bin_path = resolve_binary_path(target_name)

    if target_bin_path is None:
        sys.exit(1)

    target = Target(
        name=target_name,
        path=target_bin_path,
        timeout=1000,
        env={**dict(os.environ), **(args.env or {})},
        argv=args.target[1:],
        target_input=input,
    )

    return target


def resolve_binary_path(target_bin_name: str) -> str:
    """Resolve the full path of a target binary"""

    if os.path.isabs(target_bin_name) or "/" in target_bin_name:
        if os.path.exists(target_bin_name):

            if os.access(target_bin_name, os.X_OK):
                os.path.abspath(target_bin_name)
            else:
                pivot_logger.error(f"{target_bin_name} is not executable")
                return None

    potential_path = os.path.join("/mnt/binaries", target_bin_name)

    if os.path.exists(potential_path) and os.access(potential_path, os.X_OK):
        return potential_path

    full_path = shutil.which(target_bin_name)
    if full_path:
        return full_path

    pivot_logger.error(f"{target_bin_name} not found.")
    return None


def check_target_bin(target: str) -> None:

    target_path = f"/mnt/binaries/{target}"

    if not os.path.isfile(target_path):
        pivot_logger.error(f"Program {target} does not exist.")
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
        pivot_logger.error("64-bit binaries are not supported by the program.")
        sys.exit(1)

    return

def detect_input_type(args):
    if args.env and any("@@" in v for v in args.env.values()):
        return "env"
    if "@@" in args.target:
        return "argv"
    return "stdin"
