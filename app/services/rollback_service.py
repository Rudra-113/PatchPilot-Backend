from pathlib import Path
from typing import Any


def rollback_patch(
    patch_result: dict[str, Any],
    repository_path: str,
) -> dict[str, Any]:

    if not patch_result:
        return {
            "status": "ROLLBACK_FAILED",
            "reason": "Patch result is empty.",
        }

    if patch_result.get("status") != "PATCH_APPLIED":
        return {
            "status": "ROLLBACK_FAILED",
            "reason": (
                "The patch was not successfully applied."
            ),
        }

    backup_path = patch_result.get("backup")

    if not backup_path:
        return {
            "status": "ROLLBACK_FAILED",
            "reason": (
                "No backup file was created for this patch."
            ),
        }

    backup_file = Path(backup_path)

    if not backup_file.exists():
        return {
            "status": "ROLLBACK_FAILED",
            "reason": (
                f"Backup file was not found: {backup_path}"
            ),
        }

    target_file = Path(
        patch_result.get("file", "")
    )

    if not target_file.exists():

        repository_root = Path(
            repository_path
        ).resolve()

        candidate = (
            repository_root
            / target_file.name
        )

        if candidate.exists():
            target_file = candidate

        else:
            matches = list(
                repository_root.rglob(
                    target_file.name
                )
            )

            if not matches:
                return {
                    "status": "ROLLBACK_FAILED",
                    "reason": (
                        "Original patched file "
                        "could not be found."
                    ),
                }

            target_file = matches[0]

    try:
        backup_content = backup_file.read_text(
            encoding="utf-8",
            errors="replace",
        )

        target_file.write_text(
            backup_content,
            encoding="utf-8",
        )

    except OSError as exc:
        return {
            "status": "ROLLBACK_FAILED",
            "reason": str(exc),
        }

    return {
        "status": "ROLLED_BACK",
        "file": str(target_file),
        "backup": str(backup_file),
        "restored": True,
        "message": (
            "The original source code was restored "
            "successfully from the PatchPilot backup."
        ),
    }