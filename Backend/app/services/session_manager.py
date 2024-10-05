from fastapi import HTTPException, Depends
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.models.user import User

class SessionManager:
    def __init__(self):
        self.active_sessions = {}

    def create_session(self, user_id: int):
        # Logic to create a session and store it in active_sessions
        self.active_sessions[user_id] = {"session_token": "random_token_value"}

    def revoke_session(self, user_id: int):
        # Logic to revoke a specific session
        if user_id in self.active_sessions:
            del self.active_sessions[user_id]
        else:
            raise HTTPException(status_code=400, detail="Session not found")

    def revoke_all_sessions(self, user_id: int):
        # Logic to revoke all sessions for a specific user
        self.active_sessions = {k: v for k, v in self.active_sessions.items() if k != user_id}
        return {"msg": "All sessions revoked"}

    def check_session(self, user_id: int, session_token: str):
        # Logic to validate a session token
        session = self.active_sessions.get(user_id)
        if session and session.get("session_token") == session_token:
            return True
        else:
            raise HTTPException(status_code=401, detail="Invalid session")
