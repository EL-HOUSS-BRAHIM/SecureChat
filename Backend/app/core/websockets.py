from fastapi import WebSocket, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.models import user, message
from app.core.encryption import encrypt_message
from app.core.security import SECRET_KEY, ALGORITHM
import json
import jwt

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, user_id: int):
        self.active_connections[user_id] = websocket
    
    def disconnect(self, user_id: int):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
    
    async def send_personal_message(self, message: str, user_id: int):
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_text(message)

manager = ConnectionManager()

# Main WebSocket handling logic
async def handle_websocket(websocket: WebSocket, user_id: int, db: Session):
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            receiver = db.query(user.User).filter(user.User.id == message_data['receiver_id']).first()
            if not receiver:
                await websocket.send_text(json.dumps({"error": "Receiver not found"}))
                continue
            
            encrypted_content = encrypt_message(message_data['content'], receiver.public_key)
            
            new_message = message.Message(
                sender_id=user_id,
                receiver_id=receiver.id,
                encrypted_content=encrypted_content
            )
            
            db.add(new_message)
            db.commit()
            
            # Send the encrypted message to the receiver
            await manager.send_personal_message(json.dumps({
                "sender_id": user_id,
                "encrypted_content": encrypted_content
            }), receiver.id)
            
            # Send a confirmation to the sender
            await websocket.send_text(json.dumps({"status": "Message sent"}))
    except Exception as e:
        print(f"Error in handle_websocket: {str(e)}")
    finally:
        manager.disconnect(user_id)

# WebSocket endpoint for establishing the connection
async def websocket_endpoint(websocket: WebSocket, user_id: int, db: Session = Depends(get_db)):
    try:
        # Extract the token from the Sec-WebSocket-Protocol header
        token = websocket.headers.get("sec-websocket-protocol")
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not provided")

        # Verify the token
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        except jwt.PyJWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        # Query the database for the user
        current_user = db.query(user.User).filter(user.User.email == username).first()
        if not current_user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Perform user ID check
        if current_user.id != user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User ID mismatch")
        
        # Accept the connection after authentication and checks
        await websocket.accept(subprotocol=token)

        # Handle the WebSocket communication
        await handle_websocket(websocket, user_id, db)

    except HTTPException as http_error:
        # Log WebSocket-specific errors
        print(f"WebSocket error: {http_error.detail}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
    except Exception as e:
        # Handle unexpected errors
        print(f"WebSocket error: {str(e)}")
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)