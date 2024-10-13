from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.api import auth, friends, messages, settings, media
from app.core.websockets import websocket_endpoint
from app.core.security import get_current_user

app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Replace with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers from different modules
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(friends.router, prefix="/friends", tags=["friends"])
app.include_router(messages.router, prefix="/messages", tags=["messages"])
app.include_router(settings.router, prefix="/settings", tags=["settings"])
app.include_router(media.router, prefix="/media", tags=["media"])

# Add WebSocket endpoint
app.add_api_websocket_route("/ws/{user_id}", websocket_endpoint)

# Add this middleware to check for authentication
@app.middleware("http")
async def authenticate(request: Request, call_next):
    if request.url.path in ["/auth/login", "/auth/register", "/", "/health"]:  # Skip auth for these endpoints
        response = await call_next(request)
        return response

    token = request.cookies.get("access_token")
    if token:
        try:
            token = token.split()[1]  # Remove "Bearer " prefix
            user = get_current_user(token)
            request.state.user = user
        except:
            pass
    response = await call_next(request)
    return response

# Use this dependency in your route handlers
async def get_current_user_from_request(request: Request):
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

# Root endpoint
@app.get("/")
async def read_root():
    return {"message": "Welcome to the Real-Time Chat Application API"}

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# Example protected route
@app.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user_from_request)):
    return {"message": "This is a protected route", "user": current_user}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)