from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.models import message, user
from app.core.encryption import decrypt_message
from app.core.security import get_current_user, TokenData
from typing import List
from pydantic import BaseModel

router = APIRouter()

class MessageResponse(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    content: str
    created_at: str

@router.get("/", response_model=List[MessageResponse])
def get_messages(other_user_id: int, db: Session = Depends(get_db), current_user: TokenData = Depends(get_current_user)):
    return get_decrypted_messages(current_user.user_id, other_user_id, db)

def get_decrypted_messages(user_id: int, other_user_id: int, db: Session):
    user_data = db.query(user.User).filter(user.User.id == user_id).first()
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")

    messages = db.query(message.Message).filter(
        ((message.Message.sender_id == user_id) & (message.Message.receiver_id == other_user_id)) |
        ((message.Message.sender_id == other_user_id) & (message.Message.receiver_id == user_id))
    ).order_by(message.Message.created_at.desc()).all()

    decrypted_messages = []
    for msg in messages:
        if msg.receiver_id == user_id:
            # Decrypt the message if the user is the receiver
            decrypted_content = decrypt_message(msg.encrypted_content, user_data.private_key)
        else:
            # If the user is the sender, they can't decrypt the message
            decrypted_content = "[Encrypted]"
        
        decrypted_messages.append(MessageResponse(
            id=msg.id,
            sender_id=msg.sender_id,
            receiver_id=msg.receiver_id,
            content=decrypted_content,
            created_at=str(msg.created_at)
        ))

    return decrypted_messages