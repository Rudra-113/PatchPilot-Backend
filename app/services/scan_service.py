import json
from pathlib import Path

from app.scanners.semgrep import SemgrepScanner


SCAN_ROOT = Path("scans")
CACHE_ROOT = Path("scan_cache")


def scan_repository(repository_id: str) -> dict:
    repository_path = SCAN_ROOT / repository_id

    if not repository_path.exists():
        raise FileNotFoundError(
            f"Repository {repository_id} was not found."
        )

    if not repository_path.is_dir():
        raise ValueError(
            f"Repository path {repository_id} is not a directory."
        )

    # Check cached scan first
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)

    cache_file = CACHE_ROOT / f"{repository_id}.json"

    if cache_file.exists():
        try:
            return json.loads(
                cache_file.read_text(
                    encoding="utf-8"
                )
            )
        except (OSError, json.JSONDecodeError):
            # If cache is corrupted, run a fresh scan
            pass

    # Run Semgrep only when no valid cache exists
    scanner = SemgrepScanner()

    results = scanner.scan(str(repository_path))

    # Save normalized results
    cache_file.write_text(
        json.dumps(
            results,
            indent=2,
        ),
        encoding="utf-8",
    )

    return results