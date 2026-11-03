import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


VALIDATION_ROOT = Path("validation_runs")


def validate_patch(
    repository_id: str,
    vulnerability: dict[str, Any],
    patch: dict[str, Any],
    repository_path: str,
) -> dict[str, Any]:

    vulnerability_id = vulnerability.get("id")

    # ---------------------------------------------------------
    # 1. Validate patch status
    # ---------------------------------------------------------

    if patch.get("status") != "PATCH_READY":
        return {
            "status": "VALIDATION_FAILED",
            "vulnerability_id": vulnerability_id,
            "reason": "Patch is not ready for validation.",
        }

    old_code = patch.get("old_code", "")
    new_code = patch.get("new_code", "")

    # ---------------------------------------------------------
    # 2. Detect false-positive / no-op patch
    # ---------------------------------------------------------

    if old_code.strip() == new_code.strip():
        return {
            "status": "FALSE_POSITIVE",
            "vulnerability_id": vulnerability_id,
            "rule_id": vulnerability.get("rule_id"),
            "vulnerability_fixed": False,
            "code_changed": False,
            "message": (
                "No code changes were required. "
                "The AI determined that this finding is a "
                "false positive or already securely implemented."
            ),
        }

    # ---------------------------------------------------------
    # 3. Validate repository
    # ---------------------------------------------------------

    source_root = Path(repository_path).resolve()

    if not source_root.exists():
        raise FileNotFoundError(
            f"Repository not found: {repository_path}"
        )

    if not source_root.is_dir():
        raise ValueError(
            f"Repository path is not a directory: "
            f"{repository_path}"
        )

    # ---------------------------------------------------------
    # 4. Create isolated validation copy
    # ---------------------------------------------------------

    validation_dir = (
        VALIDATION_ROOT
        / repository_id
        / vulnerability_id
    )

    if validation_dir.exists():
        shutil.rmtree(validation_dir)

    validation_dir.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copytree(
        source_root,
        validation_dir,
    )

    # ---------------------------------------------------------
    # 5. Locate target file
    # ---------------------------------------------------------

    original_file = Path(
        patch.get("file", "")
    )

    try:
        original_file = original_file.resolve()
    except OSError:
        pass

    try:
        relative_file = original_file.relative_to(
            source_root
        )
    except ValueError:
        relative_file = Path(
            vulnerability.get("file", "")
        )

        # Semgrep may return an absolute path.
        # Try to recover only the portion after the repository.
        if relative_file.is_absolute():
            relative_file = Path(
                relative_file.name
            )

    target_file = validation_dir / relative_file

    if not target_file.exists():

        filename = original_file.name

        matches = list(
            validation_dir.rglob(filename)
        )

        if not matches:
            return {
                "status": "VALIDATION_FAILED",
                "vulnerability_id": vulnerability_id,
                "reason": (
                    "Target file was not found in "
                    "the validation copy."
                ),
            }

        target_file = matches[0]

    # ---------------------------------------------------------
    # 6. Read target source
    # ---------------------------------------------------------

    source_code = target_file.read_text(
        encoding="utf-8",
        errors="replace",
    )

    # ---------------------------------------------------------
    # 7. Ensure patch target exists exactly once
    # ---------------------------------------------------------

    occurrences = source_code.count(
        old_code
    )

    if occurrences != 1:
        return {
            "status": "VALIDATION_FAILED",
            "vulnerability_id": vulnerability_id,
            "reason": (
                "Patch could not be safely applied. "
                f"Expected old_code exactly once, "
                f"found {occurrences} occurrences."
            ),
        }

    # ---------------------------------------------------------
    # 8. Apply patch to validation copy
    # ---------------------------------------------------------

    patched_code = source_code.replace(
        old_code,
        new_code,
        1,
    )

    target_file.write_text(
        patched_code,
        encoding="utf-8",
    )

    # ---------------------------------------------------------
    # 9. Run Semgrep against patched copy
    # ---------------------------------------------------------

    command = [
        "semgrep",
        "--config",
        "auto",
        "--json",
        "--no-git-ignore",
        str(validation_dir),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
        )

    except subprocess.TimeoutExpired:
        return {
            "status": "VALIDATION_FAILED",
            "vulnerability_id": vulnerability_id,
            "reason": (
                "Validation Semgrep scan timed out."
            ),
        }

    except FileNotFoundError:
        return {
            "status": "VALIDATION_FAILED",
            "vulnerability_id": vulnerability_id,
            "reason": (
                "Semgrep is not installed or "
                "not available in PATH."
            ),
        }

    # ---------------------------------------------------------
    # 10. Parse Semgrep result
    # ---------------------------------------------------------

    if not result.stdout.strip():
        return {
            "status": "VALIDATION_FAILED",
            "vulnerability_id": vulnerability_id,
            "reason": (
                "Semgrep returned no output "
                "during validation."
            ),
        }

    try:
        scan_data = json.loads(
            result.stdout
        )

    except json.JSONDecodeError:
        return {
            "status": "VALIDATION_FAILED",
            "vulnerability_id": vulnerability_id,
            "reason": (
                "Could not parse Semgrep validation output."
            ),
        }

    findings = scan_data.get(
        "results",
        [],
    )

    # ---------------------------------------------------------
    # 11. Check whether original rule still exists
    # ---------------------------------------------------------

    original_rule = vulnerability.get(
        "rule_id"
    )

    remaining_findings = [
        finding
        for finding in findings
        if finding.get("check_id") == original_rule
    ]

    vulnerability_fixed = (
        len(remaining_findings) == 0
    )

    # ---------------------------------------------------------
    # 12. Return validation result
    # ---------------------------------------------------------

    if vulnerability_fixed:

        return {
            "status": "VALIDATED",
            "vulnerability_id": vulnerability_id,
            "rule_id": original_rule,
            "target_file": str(target_file),
            "validation_directory": str(
                validation_dir
            ),
            "original_findings": len(findings),
            "remaining_matching_findings": 0,
            "vulnerability_fixed": True,
            "code_changed": True,
            "message": (
                "The patch changed the code and "
                "the original vulnerability was no "
                "longer detected after validation."
            ),
        }

    return {
        "status": "VALIDATION_FAILED",
        "vulnerability_id": vulnerability_id,
        "rule_id": original_rule,
        "target_file": str(target_file),
        "validation_directory": str(
            validation_dir
        ),
        "original_findings": len(findings),
        "remaining_matching_findings": len(
            remaining_findings
        ),
        "vulnerability_fixed": False,
        "code_changed": True,
        "message": (
            "The vulnerability is still detected "
            "after applying the patch."
        ),
    }