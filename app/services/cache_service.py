import json
from pathlib import Path
from typing import Any


CACHE_ROOT = Path("patchpilot_cache")


def _repository_cache(
    repository_id: str,
) -> Path:
    path = CACHE_ROOT / repository_id
    path.mkdir(
        parents=True,
        exist_ok=True,
    )
    return path


def save_analysis(
    repository_id: str,
    vulnerability_id: str,
    analysis: dict[str, Any],
) -> None:

    path = (
        _repository_cache(repository_id)
        / f"analysis_{vulnerability_id}.json"
    )

    path.write_text(
        json.dumps(
            analysis,
            indent=2,
        ),
        encoding="utf-8",
    )


def get_analysis(
    repository_id: str,
    vulnerability_id: str,
) -> dict[str, Any] | None:

    path = (
        _repository_cache(repository_id)
        / f"analysis_{vulnerability_id}.json"
    )

    if not path.exists():
        return None

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ):
        return None


def save_patch(
    repository_id: str,
    vulnerability_id: str,
    patch: dict[str, Any],
) -> None:

    path = (
        _repository_cache(repository_id)
        / f"patch_{vulnerability_id}.json"
    )

    path.write_text(
        json.dumps(
            patch,
            indent=2,
        ),
        encoding="utf-8",
    )


def get_patch(
    repository_id: str,
    vulnerability_id: str,
) -> dict[str, Any] | None:

    path = (
        _repository_cache(repository_id)
        / f"patch_{vulnerability_id}.json"
    )

    if not path.exists():
        return None

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ):
        return None