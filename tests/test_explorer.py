import pytest
from pivot.dataclass_utils import Target, TargetInput
from pivot.utils import *
from pivot.exploit_utils import *
from typing import List, Dict
from dataclasses import dataclass, field
import logging
import os
import subprocess

for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

logging.basicConfig(
    filename="test.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode="w",  # optional: start fresh every run
)

@dataclass
class test_target:
    name: str
    timeout: int
    target_input_path: str
    arg_config: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)

targets = {
    "may": test_target(
        name="may",
        timeout=100,
        target_input_path="/crash_inputs/may_input",
        arg_config=["may", "@@"],
        env=None
    ),
    "june": test_target(
        name="june",
        timeout=100,
        target_input_path="/crash_inputs/june_input",
        arg_config=["june", "@@"],
        env=None
    ),
    "july": test_target(
        name="july",
        timeout=100,
        target_input_path="/crash_inputs/july_input",
        arg_config=["july", "@@"],
        env=None
    ),
    "aspell": test_target(
        name="aspell",
        timeout=100,
        target_input_path="/crash_inputs/aspell_input",
        arg_config=["aspell", "c"],
        env=None
    ),
}


ENTRYPOINT = "pivot"

@pytest.mark.parametrize("target_key", targets.keys())
def test_target(target_key: str):

    target = targets.get(target_key)
    assert target is not None, f"Target {target_key} not found in targets dictionary"

    logging.info(f"Testing target: {target.name}")

    invocation = [
        ENTRYPOINT, "--input", target.target_input_path
    ]
    invocation.append("--target")
    invocation.extend(target.arg_config)
    invocation.append("--verbose")

    if target.env:
        invocation.append("--env")
        for key, value in target.env.items():
            invocation.append(f"{key}={value}")

    exploit_command = " ".join(invocation)
    process = subprocess.Popen(
        exploit_command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    start_time = time.time()

    try:
        stdout, stderr = process.communicate(timeout=target.timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()

    end_time = time.time()
    elapsed_time = end_time - start_time
    output = stdout + stderr

    mutation_count = mutations(output)
    tree_depth = depth(output)
    logging.info(f"generated mutations={mutation_count}, state tree depth={tree_depth}, time={elapsed_time:.3f}s")

    assert process.returncode == 0
    shutil.rmtree(f"/app/{target.name}_exploit")


def mutations(output: str) -> int:
    import re

    match = re.findall(r'mutations generated:\s+(\d+)', output)

    if match:
        count = int(match[0])
    else:
        raise AssertionError("No mutation count found in output")
        
    return count

def depth(output: str) -> int:
    import re

    match = re.findall(r'state tree level:\s+(\d+)', output)

    if match:
        count = int(match[0])
    else:
        raise AssertionError("No tree depth number found in output")
        
    return count
