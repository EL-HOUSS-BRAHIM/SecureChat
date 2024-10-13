from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Query, WebSocket
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.models import media as MediaModel, user as UserModel, message as MessageModel
from app.core.encryption import encrypt_binary_data, decrypt_binary_data
from app.core.security import verify_ws_token
from typing import List
from pydantic import BaseModel
import uuid
import mimetypes
import json

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

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File size exceeds maximum limit")

    user = db.query(UserModel.User).filter(UserModel.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        encrypted_content = encrypt_binary_data(content, user.public_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")

    filename = f"{uuid.uuid4()}.{file.filename.rsplit('.', 1)[1].lower()}"
    mime_type = mimetypes.guess_type(file.filename)[0]

    media = MediaModel.Media(
        user_id=user_id,
        filename=filename,
        mime_type=mime_type,
        size=len(content),
        encrypted_content=encrypted_content
    )

    db.add(media)
    db.commit()

    return {"msg": "File uploaded successfully", "media_id": media.id}

@router.get("/retrieve/{media_id}")
async def retrieve_media(media_id: int, user_id: int, db: Session = Depends(get_db)):
    media = db.query(MediaModel.Media).filter(MediaModel.Media.id == media_id, MediaModel.Media.user_id == user_id).first()
    if not media:
        raise HTTPException(status_code=404, detail="Media not found")

    user = db.query(UserModel.User).filter(UserModel.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        decrypted_content = decrypt_binary_data(media.encrypted_content, user.private_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")

    def iterfile():
        yield decrypted_content

    return StreamingResponse(iterfile(), media_type=media.mime_type)

@router.post("/share")
async def share_media(media_id: int, sender_id: int, receiver_id: int, db: Session = Depends(get_db)):
    media = db.query(MediaModel.Media).filter(MediaModel.Media.id == media_id, MediaModel.Media.user_id == sender_id).first()
    if not media:
        raise HTTPException(status_code=404, detail="Media not found")

    sender = db.query(UserModel.User).filter(UserModel.User.id == sender_id).first()
    receiver = db.query(UserModel.User).filter(UserModel.User.id == receiver_id).first()
    if not sender or not receiver:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        # Decrypt the content with sender's private key
        decrypted_content = decrypt_binary_data(media.encrypted_content, sender.private_key)
        # Re-encrypt the content with receiver's public key
        re_encrypted_content = encrypt_binary_data(decrypted_content, receiver.public_key)

        # Create a new media entry for the receiver
        shared_media = MediaModel.Media(
            user_id=receiver_id,
            filename=media.filename,
            mime_type=media.mime_type,
            size=media.size,
            encrypted_content=re_encrypted_content
        )
        db.add(shared_media)
        db.flush()

        # Create a new message with the media
        message = MessageModel.Message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            content=f"Shared media: {media.filename}",
            media_id=shared_media.id
        )
        db.add(message)
        db.commit()

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to share media: {str(e)}")

    return {"msg": "Media shared successfully", "message_id": message.id, "shared_media_id": shared_media.id}

@router.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, db: Session = Depends(get_db)):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            token = message_data.get("token")
            if not token or not verify_ws_token(token):
                await websocket.close(code=4001)
                return

            if message_data.get("type") == "share_media":
                media_id = message_data.get("media_id")
                receiver_id = message_data.get("receiver_id")
                
                try:
                    result = await share_media(media_id, user_id, receiver_id, db)
                    await websocket.send_text(json.dumps(result))
                except HTTPException as e:
                    await websocket.send_text(json.dumps({"error": str(e.detail)}))
                except Exception as e:
                    await websocket.send_text(json.dumps({"error": "An unexpected error occurred"}))

    except Exception as e:
        print(f"WebSocket Error: {str(e)}")
    finally:
        await websocket.close()

@router.delete("/delete/{media_id}", response_model=dict)
async def delete_media(media_id: int, user_id: int, db: Session = Depends(get_db)):
    media = db.query(MediaModel.Media).filter(MediaModel.Media.id == media_id, MediaModel.Media.user_id == user_id).first()
    if not media:
        raise HTTPException(status_code=404, detail="Media not found")

    try:
        db.delete(media)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete media: {str(e)}")

    return {"msg": "Media deleted successfully"}

@router.get("/list", response_model=List[MediaResponse])
def list_media(user_id: int, db: Session = Depends(get_db), skip: int = 0, limit: int = 20):
    try:
        media_files = db.query(MediaModel.Media).filter(MediaModel.Media.user_id == user_id)\
            .order_by(MediaModel.Media.created_at.desc())\
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve media list: {str(e)}")

