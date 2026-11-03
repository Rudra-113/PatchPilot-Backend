from pathlib import Path
from typing import Any
import shutil


def apply_patch(
    patch: dict[str, Any],
    repository_path: str,
) -> dict[str, Any]:

    if patch.get("status") != "PATCH_READY":
        raise ValueError(
            "Patch is not ready for application."
        )

    source_file = Path(patch["file"])

    if not source_file.exists():
        candidate = Path(repository_path) / source_file.name

        if candidate.exists():
            source_file = candidate
        else:
            matches = list(
                Path(repository_path).rglob(
                    source_file.name
                )
            )

            if not matches:
                raise FileNotFoundError(
                    f"Patch target file not found: "
                    f"{patch['file']}"
                )

            source_file = matches[0]

    source_code = source_file.read_text(
        encoding="utf-8",
        errors="replace",
    )

    old_code = patch["old_code"]
    new_code = patch["new_code"]

    occurrences = source_code.count(old_code)

    if occurrences != 1:
        raise ValueError(
            "Patch application aborted: "
            f"old_code occurs {occurrences} times."
        )

    patched_code = source_code.replace(
        old_code,
        new_code,
        1,
    )

    # Create backup
    backup_file = source_file.with_suffix(
        source_file.suffix + ".patchpilot-backup"
    )

    shutil.copy2(
        source_file,
        backup_file,
    )

    # Apply patch
    source_file.write_text(
        patched_code,
        encoding="utf-8",
    )

    return {
        "status": "PATCH_APPLIED",
        "file": str(source_file),
        "backup": str(backup_file),
        "changed": True,
        "old_code": old_code,
        "new_code": new_code,
    }