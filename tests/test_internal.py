import pytest
from pivot.dataclass_utils import Target, TargetInput
from pivot.utils import *
from pivot.exploit_utils import *
from typing import List, Dict
from dataclasses import dataclass, field
import logging
import os
import subprocess
import tempfile

for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

logging.basicConfig(
    filename="test2.log",
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
    "iwconfig": test_target(
        name="iwconfig",
        timeout=100,
        target_input_path="/crash_inputs/iwconfig_input",
        arg_config=["iwconfig", "@@"],
        env=None,
    ),
    "vuln": test_target(
        name="vuln",
        timeout=100,
        target_input_path="/crash_inputs/vuln_input",
        arg_config=["vuln"],
        env=None
    ),
    "ncompress": test_target(
        name="ncompress",
        timeout=100,
        target_input_path="/crash_inputs/ncompress_input",
        arg_config=["ncompress", "@@"],
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

    if target.env:
        invocation.append("--env")
        for key, value in target.env.items():
            invocation.append(f"{key}={value}")

    logging.info(f"Invocation: {' '.join(invocation)}")
    try:

        exploit_command = " ".join(invocation)
        logging.info(f"System command: {exploit_command}")
        result = subprocess.run(
            exploit_command,
            timeout=target.timeout,
            shell=True,
            capture_output=True,
            text=True
        )

        output = result.stdout
        logging.info(f"Output: {output}")

        assert result.returncode == 0
        logging.info(f"Test for target {target.name} passed successfully.")
        shutil.rmtree(f"/app/{target.name}_exploit")


    except Exception as e:
        logging.error(f"Failed to start process: {e}")
        raise