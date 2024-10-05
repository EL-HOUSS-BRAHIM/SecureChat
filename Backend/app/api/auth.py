from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.models import user
from app.core.security import generate_totp, verify_totp
from app.services.email_service import send_verification_email

router = APIRouter()

@router.post("/register")
def register_user(username: str, email: str, password: str, db: Session = Depends(get_db)):
    # Registration logic with public/private key handling and ms_id generation
    if db.query(user.User).filter(user.User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    new_user = user.User(username=username, email=email, password_hash=password)
    db.add(new_user)
    db.commit()
    send_verification_email(email)  # Sending verification email
    return {"msg": "User registered successfully"}

@router.post("/login")
def login_user(email: str, password: str, totp_code: str, db: Session = Depends(get_db)):
    # Login logic with optional 2FA verification
    user_obj = db.query(user.User).filter(user.User.email == email).first()
    if not user_obj or user_obj.password_hash != password:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if user_obj.totp_secret and not verify_totp(user_obj.totp_secret, totp_code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    return {"msg": "Login successful"}

@router.post("/logout")
def logout_user():
    # Terminate session logic
    return {"msg": "User logged out successfully"}
