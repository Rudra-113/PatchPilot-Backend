from typing import Any

from app.services.ai_service import analyze_vulnerability
from app.services.cache_service import (
    get_analysis,
    save_analysis,
    get_patch,
    save_patch,
)
from app.services.diff_service import generate_patch_diff
from app.services.patch_service import generate_patch
from app.services.scan_service import scan_repository
from app.services.validation_service import validate_patch
from app.services.sandbox_service import run_sandbox


def _find_vulnerability(
    repository_id: str,
    vulnerability_id: str,
) -> dict[str, Any]:

    result = scan_repository(
        repository_id
    )

    vulnerability = next(
        (
            item
            for item in result.get(
                "vulnerabilities",
                [],
            )
            if item.get("id") == vulnerability_id
        ),
        None,
    )

    if vulnerability is None:
        raise ValueError(
            f"Vulnerability "
            f"{vulnerability_id} was not found."
        )

    return vulnerability


def _get_or_create_analysis(
    repository_id: str,
    vulnerability: dict[str, Any],
    repository_path: str,
) -> dict[str, Any]:

    vulnerability_id = vulnerability["id"]

    cached = get_analysis(
        repository_id,
        vulnerability_id,
    )

    if cached is not None:
        return cached

    analysis = analyze_vulnerability(
        vulnerability,
        repository_path=repository_path,
    )

    save_analysis(
        repository_id,
        vulnerability_id,
        analysis,
    )

    return analysis


def _get_or_create_patch(
    repository_id: str,
    vulnerability: dict[str, Any],
    analysis: dict[str, Any],
    repository_path: str,
) -> dict[str, Any]:

    vulnerability_id = vulnerability["id"]

    cached = get_patch(
        repository_id,
        vulnerability_id,
    )

    if cached is not None:
        return cached

    patch = generate_patch(
        vulnerability=vulnerability,
        analysis=analysis,
        repository_path=repository_path,
    )

    save_patch(
        repository_id,
        vulnerability_id,
        patch,
    )

    return patch


def remediate_vulnerability(
    repository_id: str,
    vulnerability_id: str,
) -> dict[str, Any]:

    repository_path = (
        f"scans/{repository_id}"
    )

    # ---------------------------------------------------------
    # 1. Find vulnerability
    # ---------------------------------------------------------

    vulnerability = _find_vulnerability(
        repository_id,
        vulnerability_id,
    )

    # ---------------------------------------------------------
    # 2. AI analysis
    # ---------------------------------------------------------

    analysis = _get_or_create_analysis(
        repository_id,
        vulnerability,
        repository_path,
    )

    analysis_text = (
        str(analysis.get("title", ""))
        + " "
        + str(
            analysis.get(
                "patch_strategy",
                "",
            )
        )
        + " "
        + str(
            analysis.get(
                "remediation",
                "",
            )
        )
    ).lower()

    # ---------------------------------------------------------
    # 3. False-positive detection
    # ---------------------------------------------------------

    if (
        "false positive" in analysis_text
        or "no remediation" in analysis_text
        or "no code changes" in analysis_text
    ):
        return {
            "repository_id": repository_id,
            "vulnerability_id": vulnerability_id,
            "status": "FALSE_POSITIVE",
            "vulnerability": vulnerability,
            "analysis": analysis,
            "patch": None,
            "diff": {
                "status": "NO_CHANGES",
                "files_changed": 0,
                "lines_added": 0,
                "lines_removed": 0,
                "diff": "",
                "message": (
                    "No code changes are required."
                ),
            },
            "sandbox": None,
            "validation": {
                "status": "FALSE_POSITIVE",
                "vulnerability_fixed": False,
                "code_changed": False,
                "message": (
                    "AI analysis determined that "
                    "this finding does not require "
                    "a code change."
                ),
            },
        }

    # ---------------------------------------------------------
    # 4. Generate patch
    # ---------------------------------------------------------

    patch = _get_or_create_patch(
        repository_id,
        vulnerability,
        analysis,
        repository_path,
    )

    if patch.get("status") != "PATCH_READY":
        return {
            "repository_id": repository_id,
            "vulnerability_id": vulnerability_id,
            "status": "PATCH_NOT_READY",
            "vulnerability": vulnerability,
            "analysis": analysis,
            "patch": patch,
            "diff": None,
            "sandbox": None,
            "validation": None,
        }

    # ---------------------------------------------------------
    # 5. Generate diff
    # ---------------------------------------------------------

    diff = generate_patch_diff(
        patch=patch,
        repository_path=repository_path,
    )

    if diff.get("status") != "DIFF_READY":
        return {
            "repository_id": repository_id,
            "vulnerability_id": vulnerability_id,
            "status": "DIFF_FAILED",
            "vulnerability": vulnerability,
            "analysis": analysis,
            "patch": patch,
            "diff": diff,
            "sandbox": None,
            "validation": None,
        }

    # ---------------------------------------------------------
    # 6. Validate patch
    #
    # This creates an isolated validation copy and
    # applies the patch there.
    # ---------------------------------------------------------

    validation = validate_patch(
        repository_id=repository_id,
        vulnerability=vulnerability,
        patch=patch,
        repository_path=repository_path,
    )

    if validation.get("status") != "VALIDATED":
        return {
            "repository_id": repository_id,
            "vulnerability_id": vulnerability_id,
            "status": "VALIDATION_FAILED",
            "vulnerability": vulnerability,
            "analysis": analysis,
            "patch": patch,
            "diff": diff,
            "sandbox": None,
            "validation": validation,
        }

    # ---------------------------------------------------------
    # 7. Run Docker sandbox
    # ---------------------------------------------------------

    validation_directory = validation.get(
        "validation_directory"
    )

    if not validation_directory:
        return {
            "repository_id": repository_id,
            "vulnerability_id": vulnerability_id,
            "status": "SANDBOX_FAILED",
            "vulnerability": vulnerability,
            "analysis": analysis,
            "patch": patch,
            "diff": diff,
            "sandbox": {
                "status": "SANDBOX_FAILED",
                "reason": (
                    "Validation directory was not "
                    "returned by validation service."
                ),
            },
            "validation": validation,
        }

    sandbox = run_sandbox(
        repository_id=repository_id,
        validation_directory=validation_directory,
    )

    # ---------------------------------------------------------
    # 8. Final result
    # ---------------------------------------------------------

    if sandbox.get("status") == "SANDBOX_PASSED":
        final_status = "VALIDATED"
    else:
        final_status = "SANDBOX_FAILED"

    return {
        "repository_id": repository_id,
        "vulnerability_id": vulnerability_id,
        "status": final_status,
        "vulnerability": vulnerability,
        "analysis": analysis,
        "patch": patch,
        "diff": diff,
        "sandbox": sandbox,
        "validation": validation,
    }