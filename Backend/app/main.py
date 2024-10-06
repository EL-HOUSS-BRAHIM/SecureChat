from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from app.api import auth, friends, messages, settings, media
from app.core.websockets import WebSocketManager

app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

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
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    await websocket.accept()
    await websocket_manager.connect(websocket, user_id)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket_manager.broadcast(f"User {user_id} says: {data}")
    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        await websocket_manager.disconnect(websocket, user_id)

# Root endpoint
@app.get("/")
async def read_root():
    return {"message": "Welcome to the Real-Time Chat Application API"}

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)