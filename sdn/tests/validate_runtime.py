from __future__ import annotations

import shutil
import subprocess
import os


def run_cmd(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr)


def test_containerized_ryu_runtime_path():
    if os.getenv("RUN_DOCKER_VALIDATION") != "1":
        return

    docker = shutil.which("docker")
    if not docker:
        return

    code, _ = run_cmd([docker, "compose", "-f", "docker-compose.yml", "config"])
    assert code == 0

    code, output = run_cmd([docker, "compose", "-f", "docker-compose.yml", "build", "ryu"])
    assert code == 0, output
