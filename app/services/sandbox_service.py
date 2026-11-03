import shutil
import subprocess
from pathlib import Path
from typing import Any


SANDBOX_ROOT = Path("sandbox_runs")
SANDBOX_IMAGE = "patchpilot-sandbox:latest"


def _run_docker(
    command: list[str],
    timeout: int = 120,
) -> dict[str, Any]:

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    except subprocess.TimeoutExpired:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "Docker command timed out.",
        }

    except FileNotFoundError:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "Docker CLI was not found.",
        }


def docker_available() -> bool:
    result = _run_docker(
        ["docker", "info"],
        timeout=30,
    )

    return result["returncode"] == 0


def run_sandbox(
    repository_id: str,
    validation_directory: str,
    timeout: int = 120,
) -> dict[str, Any]:

    if not docker_available():
        return {
            "status": "SANDBOX_FAILED",
            "reason": "Docker engine is not running.",
        }

    source_path = Path(
        validation_directory
    ).resolve()

    if not source_path.exists():
        return {
            "status": "SANDBOX_FAILED",
            "reason": (
                f"Validation directory not found: "
                f"{validation_directory}"
            ),
        }

    if not source_path.is_dir():
        return {
            "status": "SANDBOX_FAILED",
            "reason": "Validation path is not a directory.",
        }

    SANDBOX_ROOT.mkdir(
        parents=True,
        exist_ok=True,
    )

    run_directory = (
        SANDBOX_ROOT / repository_id
    )

    if run_directory.exists():
        shutil.rmtree(run_directory)

    run_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    container_name = (
        f"patchpilot-{repository_id[:12]}"
    )

    # Remove an old container if one exists.
    _run_docker(
        [
            "docker",
            "rm",
            "-f",
            container_name,
        ],
        timeout=30,
    )

    result: dict[str, Any] = {
        "status": "SANDBOX_FAILED",
        "repository_id": repository_id,
        "container": container_name,
        "checks": {},
    }

    try:
        # -----------------------------------------------------
        # 1. Python compilation
        # -----------------------------------------------------

        compile_command = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "128",
            "--memory",
            "512m",
            "--cpus",
            "1.0",
            "-v",
            f"{source_path}:/workspace:ro",
            SANDBOX_IMAGE,
            "python",
            "-B",
            "-m",
            "compileall",
            "-q",
            "/workspace",
        ]

        compile_result = _run_docker(
            compile_command,
            timeout=timeout,
        )

        compile_passed = (
            compile_result["returncode"] == 0
        )

        result["checks"]["compile"] = {
            "status": (
                "PASS"
                if compile_passed
                else "FAIL"
            ),
            "stdout": compile_result["stdout"],
            "stderr": compile_result["stderr"],
        }

        if not compile_passed:
            result["reason"] = (
                "Python compilation failed."
            )
            return result

        # -----------------------------------------------------
        # 2. Project tests
        # -----------------------------------------------------

        test_command = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "128",
            "--memory",
            "512m",
            "--cpus",
            "1.0",
            "-v",
            f"{source_path}:/workspace:ro",
            SANDBOX_IMAGE,
            "sh",
            "-c",
            (
                "cd /workspace && "
                "if [ -d tests ] || "
                "[ -f pytest.ini ] || "
                "[ -f pyproject.toml ] || "
                "[ -f setup.cfg ]; then "
                "python -m pytest -q; "
                "else "
                "echo 'NO_TESTS_FOUND'; "
                "fi"
            ),
        ]

        test_result = _run_docker(
            test_command,
            timeout=timeout,
        )

        test_output = (
            test_result["stdout"]
            + test_result["stderr"]
        )

        no_tests = (
            "NO_TESTS_FOUND"
            in test_output
        )

        tests_passed = (
            test_result["returncode"] == 0
        )

        if no_tests:
            test_status = "SKIPPED"
        elif tests_passed:
            test_status = "PASS"
        else:
            test_status = "FAIL"

        result["checks"]["tests"] = {
            "status": test_status,
            "stdout": test_result["stdout"],
            "stderr": test_result["stderr"],
        }

        if not tests_passed and not no_tests:
            result["reason"] = (
                "Project tests failed inside "
                "the Docker sandbox."
            )
            return result

        # -----------------------------------------------------
        # 3. Sandbox success
        #
        # Semgrep remains handled by the existing
        # validation_service. This keeps the sandbox
        # network-isolated because Semgrep's auto rules
        # may require rule downloads.
        # -----------------------------------------------------

        result["status"] = "SANDBOX_PASSED"

        result["message"] = (
            "Patched repository passed compilation "
            "and available project tests inside "
            "the isolated Docker sandbox."
        )

        return result

    finally:
        # Always remove the container.
        _run_docker(
            [
                "docker",
                "rm",
                "-f",
                container_name,
            ],
            timeout=30,
        )