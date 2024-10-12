from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.models import media, user
from app.core.encryption import encrypt_file, decrypt_file
from typing import List
from pydantic import BaseModel
import os
import uuid
import mimetypes

router = APIRouter()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

class MediaResponse(BaseModel):
    id: int
    filename: str
    mime_type: str
    size: int
    created_at: str

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@router.post("/upload", response_model=dict)
async def upload_media(file: UploadFile = File(...), user_id: int = Query(...), db: Session = Depends(get_db)):
    if not allowed_file(file.filename):
        raise HTTPException(status_code=400, detail="File type not allowed")

    if file.size > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File size exceeds maximum limit")

    content = await file.read()
    encrypted_content = encrypt_file(content)

    filename = f"{uuid.uuid4()}.{file.filename.rsplit('.', 1)[1].lower()}"
    mime_type = mimetypes.guess_type(file.filename)[0]

    media_file = media.Media(
        user_id=user_id,
        filename=filename,
        mime_type=mime_type,
        size=len(encrypted_content),
        encrypted_content=encrypted_content
    )

    db.add(media_file)
    db.commit()

    return {"msg": "File uploaded successfully", "media_id": media_file.id}

@router.get("/list", response_model=List[MediaResponse])
def list_media(
    user_id: int,
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100)
):
    media_files = db.query(media.Media).filter(media.Media.user_id == user_id)\
        .order_by(media.Media.created_at.desc())\
        .offset(skip).limit(limit).all()

    return [
        MediaResponse(
            id=m.id,
            filename=m.filename,
            mime_type=m.mime_type,
            size=m.size,
            created_at=m.created_at.isoformat()
        ) for m in media_files
    ]

@router.get("/retrieve/{media_id}")
async def retrieve_media(media_id: int, user_id: int, db: Session = Depends(get_db)):
    media_file = db.query(media.Media).filter(media.Media.id == media_id, media.Media.user_id == user_id).first()
    if not media_file:
        raise HTTPException(status_code=404, detail="Media not found")

    decrypted_content = decrypt_file(media_file.encrypted_content)

    def iterfile():
        yield decrypted_content

    return StreamingResponse(iterfile(), media_type=media_file.mime_type)

@router.delete("/delete/{media_id}", response_model=dict)
async def delete_media(media_id: int, user_id: int, db: Session = Depends(get_db)):
    media_file = db.query(media.Media).filter(media.Media.id == media_id, media.Media.user_id == user_id).first()
    if not media_file:
        raise HTTPException(status_code=404, detail="Media not found")

    db.delete(media_file)
    db.commit()

    return {"msg": "Media deleted successfully"}