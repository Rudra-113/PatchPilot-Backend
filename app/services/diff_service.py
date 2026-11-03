from pathlib import Path
from typing import Any
import difflib


def generate_patch_diff(
    patch: dict[str, Any],
    repository_path: str,
) -> dict[str, Any]:
    """
    Generate a unified diff for an AI-generated patch
    without modifying the repository.
    """

    if patch.get("status") != "PATCH_READY":
        return {
            "status": "DIFF_FAILED",
            "reason": "Patch is not ready.",
        }

    old_code = patch.get("old_code", "")
    new_code = patch.get("new_code", "")
    patch_file = patch.get("file", "")

    if not old_code.strip():
        return {
            "status": "DIFF_FAILED",
            "reason": "Patch old_code is empty.",
        }

    if old_code == new_code:
        return {
            "status": "NO_CHANGES",
            "file": patch_file,
            "files_changed": 0,
            "lines_added": 0,
            "lines_removed": 0,
            "diff": "",
            "message": (
                "The patch does not modify the source code."
            ),
        }

    repository_root = Path(
        repository_path
    ).resolve()

    source_file = Path(
        patch_file
    )

    if not source_file.exists():
        candidate = (
            repository_root
            / source_file.name
        )

        if candidate.exists():
            source_file = candidate

        else:
            matches = list(
                repository_root.rglob(
                    source_file.name
                )
            )

            if not matches:
                return {
                    "status": "DIFF_FAILED",
                    "reason": (
                        f"Patch target file was not found: "
                        f"{patch_file}"
                    ),
                }

            source_file = matches[0]

    try:
        source_code = source_file.read_text(
            encoding="utf-8",
            errors="replace",
        )

    except OSError as exc:
        return {
            "status": "DIFF_FAILED",
            "reason": str(exc),
        }

    occurrences = source_code.count(
        old_code
    )

    if occurrences != 1:
        return {
            "status": "DIFF_FAILED",
            "reason": (
                "The patch target must occur exactly once. "
                f"Found {occurrences} occurrences."
            ),
        }

    patched_code = source_code.replace(
        old_code,
        new_code,
        1,
    )

    diff_lines = list(
        difflib.unified_diff(
            source_code.splitlines(
                keepends=True
            ),
            patched_code.splitlines(
                keepends=True
            ),
            fromfile=str(source_file),
            tofile=str(source_file),
            lineterm="",
        )
    )

    lines_added = 0
    lines_removed = 0

    for line in diff_lines:
        if line.startswith("+++"):
            continue

        if line.startswith("---"):
            continue

        if line.startswith("+"):
            lines_added += 1

        elif line.startswith("-"):
            lines_removed += 1

    try:
        relative_file = source_file.relative_to(
            repository_root
        )
        display_file = str(relative_file)
    except ValueError:
        display_file = str(source_file)

    return {
        "status": "DIFF_READY",
        "file": display_file,
        "absolute_file": str(source_file),
        "files_changed": 1,
        "lines_added": lines_added,
        "lines_removed": lines_removed,
        "diff": "".join(diff_lines),
        "old_code": old_code,
        "new_code": new_code,
        "message": (
            "Patch diff generated successfully. "
            "No files were modified."
        ),
    }