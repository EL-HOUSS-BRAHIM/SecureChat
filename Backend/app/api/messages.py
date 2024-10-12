from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.models import message, user
from app.core.encryption import encrypt_message, decrypt_message
from typing import List
from pydantic import BaseModel

router = APIRouter()

class MessageCreate(BaseModel):
    receiver_id: int
    content: str

class MessageResponse(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    content: str
    created_at: str

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, WebSocket] = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: int):
        del self.active_connections[user_id]

    async def send_personal_message(self, message: str, user_id: int):
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_text(message)

manager = ConnectionManager()

@router.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, db: Session = Depends(get_db)):
    await manager.connect(websocket, user_id)
    try:
        while True:
            data = await websocket.receive_json()
            message_create = MessageCreate(**data)
            await send_message(message_create, user_id, db)
    except WebSocketDisconnect:
        manager.disconnect(user_id)

async def send_message(message_create: MessageCreate, sender_id: int, db: Session):
    receiver = db.query(user.User).filter(user.User.id == message_create.receiver_id).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")

    encrypted_content = encrypt_message(message_create.content, receiver.public_key)
    new_message = message.Message(
        sender_id=sender_id,
        receiver_id=message_create.receiver_id,
        encrypted_content=encrypted_content
    )
    db.add(new_message)
    db.commit()

    await manager.send_personal_message(f"New message from {sender_id}", message_create.receiver_id)

@router.get("/messages", response_model=List[MessageResponse])
def retrieve_messages(
    user_id: int,
    other_user_id: int,
    db: Session = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0)
):
    messages = db.query(message.Message).filter(
        ((message.Message.sender_id == user_id) & (message.Message.receiver_id == other_user_id)) |
        ((message.Message.sender_id == other_user_id) & (message.Message.receiver_id == user_id))
    ).order_by(message.Message.created_at.desc()).offset(offset).limit(limit).all()

    user_private_key = db.query(user.User.private_key).filter(user.User.id == user_id).scalar()

    return [
        MessageResponse(
            id=msg.id,
            sender_id=msg.sender_id,
            receiver_id=msg.receiver_id,
            content=decrypt_message(msg.encrypted_content, user_private_key),
            created_at=msg.created_at.isoformat()
        ) for msg in messages
    ]