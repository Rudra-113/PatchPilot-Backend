from fastapi import APIRouter, File, UploadFile

from app.services.repository_service import save_and_extract_repository


router = APIRouter(
    prefix="/repositories",
    tags=["Repositories"]
)


@router.post("/upload")
async def upload_repository(
    file: UploadFile = File(...)
):
    return await save_and_extract_repository(file)