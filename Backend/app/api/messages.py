from fastapi import APIRouter, WebSocket
from app.core.encryption import encrypt_message, decrypt_message

router = APIRouter()

@router.websocket("/messages/send")
async def send_message(websocket: WebSocket):
    await websocket.accept()
    data = await websocket.receive_json()
    encrypted_message = encrypt_message(data['content'], data['receiver_public_key'])
    # Logic to store encrypted message
    await websocket.send_json({"msg": "Message sent"})

@router.get("/messages/retrieve")
def retrieve_messages(sender_id: int, receiver_id: int):
    # Logic to retrieve encrypted messages
    messages = [{"content": "encrypted_message_1"}, {"content": "encrypted_message_2"}]  # Dummy messages
    decrypted_messages = [decrypt_message(msg['content'], "private_key") for msg in messages]
    return {"messages": decrypted_messages}
