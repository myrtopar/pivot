from dataclasses import dataclass, field
from typing import List, Dict, Optional
import argparse
import os
import shutil
import logging
import sys


# @@ --> argv input (inline raw bytes or file path)
# (no @@) --> stdin input
# ./autoexploit.py -i path/to/crash -- /mnt/binaries/ncompress @@
# ./autoexploit.py -i path/to/crash -- /mnt/binaries/iwconfig @@
# ./autoexploit.py -i path/to/crash -- /mnt/binaries/aspell c
# ./autoexploit.py -i path/to/crash -- /mnt/binaries/vuln


@dataclass
class TargetInput:
    type: str
    content: bytes
    file_path: Optional[str] = None

@dataclass
class Target:
    name: str
    path: str
    # cwd: str
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
                content = values.encode('utf-8')
            except Exception as e:
                parser.error(f"Invalid inline crashing input: {e}")
        setattr(namespace, self.dest, content)


def check_args() -> Target:

    parser = argparse.ArgumentParser(
        description='a script that exploits a target binary and spawns a shell'
    )

    parser.add_argument(
        '-i', '--input', 
        required=True, 
        help="Path to crash input file",
        action=CrashingInputAction
    )

    parser.add_argument(
        'target',
        nargs='+', 
        help='Target binary and necessary arguments'
    )

    args = parser.parse_args()

    if "@@" in args.target:
        input = TargetInput(type="argv", content=args.input)
    else:
        input = TargetInput(type="stdin", content=args.input)

    target_name = args.target[0]
    target_bin_path = resolve_binary_path(target_name)

    if target_bin_path is None:
        sys.exit(1)

    target = Target(
        name=target_name,
        path=target_bin_path,
        timeout=1000,
        env={},
        argv=args.target[1:],
        target_input=input
    )

    return target


def resolve_binary_path(target_bin_name: str) -> str:
    """Resolve the full path of a target binary"""
    
    if os.path.isabs(target_bin_name) or '/' in target_bin_name:
        if os.path.exists(target_bin_name):

            if os.access(target_bin_name, os.X_OK):
                os.path.abspath(target_bin_name)
            else:
                logging.error(f'{target_bin_name} is not executable')
                return None


    potential_path = os.path.join('/mnt/binaries', target_bin_name)

    if os.path.exists(potential_path) and os.access(potential_path, os.X_OK):
        return potential_path

    full_path = shutil.which(target_bin_name)
    if full_path:
        return full_path

    logging.error(f'{target_bin_name} not found.')
    return None