from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile, BadZipFile

from fastapi import HTTPException, UploadFile


UPLOAD_ROOT = Path("uploads")
EXTRACT_ROOT = Path("scans")

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_FILES = 5000


def _is_safe_path(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


async def save_and_extract_repository(file: UploadFile) -> dict:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=400,
            detail="Only ZIP repositories are supported"
        )

    repository_id = str(uuid4())

    upload_dir = UPLOAD_ROOT / repository_id
    extract_dir = EXTRACT_ROOT / repository_id

    upload_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    zip_path = upload_dir / "repository.zip"

    try:
        total_size = 0

        with zip_path.open("wb") as destination:
            while chunk := await file.read(1024 * 1024):
                total_size += len(chunk)

                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="Repository ZIP is too large. Maximum size is 50 MB."
                    )

                destination.write(chunk)

        try:
            with ZipFile(zip_path, "r") as archive:
                members = archive.infolist()

                if len(members) > MAX_FILES:
                    raise HTTPException(
                        status_code=400,
                        detail="Repository contains too many files."
                    )

                for member in members:
                    target = extract_dir / member.filename

                    if not _is_safe_path(extract_dir, target):
                        raise HTTPException(
                            status_code=400,
                            detail="Unsafe ZIP file path detected."
                        )

                archive.extractall(extract_dir)

        except BadZipFile:
            raise HTTPException(
                status_code=400,
                detail="Invalid ZIP file."
            )

        return {
            "repository_id": repository_id,
            "filename": file.filename,
            "size": total_size,
            "extracted_path": str(extract_dir),
            "status": "uploaded"
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Repository processing failed: {str(exc)}"
        )