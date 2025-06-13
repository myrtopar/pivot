import pytest
from pivot.dataclass_utils import Target, TargetInput
from pivot.utils import *
from pivot.exploit_utils import *
from typing import List, Dict
from dataclasses import dataclass, field
import logging
import os
import subprocess
import time
import statistics

N_RUNS = 5

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
    "iwconfig": test_target(
        name="iwconfig_real",
        timeout=100,
        target_input_path="/crash_inputs/iwconfig_input",
        arg_config=["iwconfig_real", "@@"],
        env=None,
    ),
    "vuln": test_target(
        name="vuln_real",
        timeout=100,
        target_input_path="/crash_inputs/vuln_input",
        arg_config=["vuln_real"],
        env=None
    ),
    "ncompress": test_target(
        name="ncompress_real",
        timeout=100,
        target_input_path="/crash_inputs/ncompress_input",
        arg_config=["ncompress_real", "@@"],
        env=None
    ),

    "stacksix": test_target(
        name="stacksix_real",
        timeout=100,
        target_input_path="/crash_inputs/stacksix_input",
        arg_config=["stacksix_real"],
        env={
            'ExploitEducation': '@@'
        }
    ),
    "picoctf_bof": test_target(
        name="picoctf_bof_real",
        timeout=100,
        target_input_path="/crash_inputs/picoctf_bof_input",
        arg_config=["picoctf_bof_real"],
        env=None,
    ),
}

ENTRYPOINT = "pivot"

import time
import statistics

N_RUNS = 10

@pytest.mark.parametrize("target_key", targets.keys())
def test_target(target_key: str):
    target = targets.get(target_key)
    assert target is not None, f"Target {target_key} not found in targets dictionary"

    logging.info(f"Testing target: {target.name}")

    all_times = []
    all_attempts = []

    for I in range(N_RUNS):
        logging.info(f"Run {I+1}/{N_RUNS}")

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

        attempt_count = attempts(output)
        logging.info(f"Run {I+1}: Attempts={attempt_count}, Time={elapsed_time:.3f}s")

        assert process.returncode == 0

        all_times.append(elapsed_time)
        all_attempts.append(attempt_count)

        shutil.rmtree(f"/app/{target.name}_exploit")

    avg_time = sum(all_times) / len(all_times)
    avg_attempts = sum(all_attempts) / len(all_attempts)

    logging.info(f"Target {target.name}: avg_time={avg_time:.3f}s, avg_attempts={avg_attempts:.2f}")



def attempts(output: str) -> int:
    import re

    matches = re.findall(r'Attempt:\s+(\d+)', output)
    if matches:
        last_attempt = int(matches[-1])
    else:
        raise AssertionError("No attempt number found in output")
        
    return last_attempt

