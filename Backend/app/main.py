from fastapi import FastAPI
from app.api import auth, friends, messages, settings, media
from app.core.websockets import WebSocketManager

app = FastAPI()

# Include routers from different modules
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(friends.router, prefix="/friends", tags=["friends"])
app.include_router(messages.router, prefix="/messages", tags=["messages"])
app.include_router(settings.router, prefix="/settings", tags=["settings"])
app.include_router(media.router, prefix="/media", tags=["media"])

# WebSocket manager for real-time messaging
websocket_manager = WebSocketManager()

# WebSocket endpoint for real-time communication
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket, user_id: int):
    await websocket_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket_manager.broadcast(f"User {user_id} says: {data}")
    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        websocket_manager.disconnect(websocket)

# Root endpoint
@app.get("/")
def read_root():
    return {"message": "Welcome to the Real-Time Chat Application API"}

# Start the FastAPI application with the command:
# uvicorn main:app --reload
