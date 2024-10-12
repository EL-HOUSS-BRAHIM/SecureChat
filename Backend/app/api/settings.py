from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.models import user
from app.core.security import generate_totp, verify_password, hash_password
from pydantic import BaseModel, EmailStr
from typing import Optional
import pyotp
import uuid

router = APIRouter()

class ProfileUpdate(BaseModel):
    username: Optional[str]
    email: Optional[EmailStr]

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class Enable2FA(BaseModel):
    password: str

class Disable2FA(BaseModel):
    password: str
    totp_code: str

@router.get("/profile", response_model=dict)
def get_profile(user_id: int, db: Session = Depends(get_db)):
    user_obj = db.query(user.User).filter(user.User.id == user_id).first()
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "username": user_obj.username,
        "email": user_obj.email,
        "ms_id": user_obj.ms_id,
        "has_2fa": bool(user_obj.totp_secret)
    }

@router.put("/profile", response_model=dict)
def update_profile(profile: ProfileUpdate, user_id: int, db: Session = Depends(get_db)):
    user_obj = db.query(user.User).filter(user.User.id == user_id).first()
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")

    if profile.username:
        user_obj.username = profile.username
    if profile.email:
        user_obj.email = profile.email

    db.commit()
    return {"msg": "Profile updated successfully"}

@router.put("/change-password", response_model=dict)
def change_password(password_change: PasswordChange, user_id: int, db: Session = Depends(get_db)):
    user_obj = db.query(user.User).filter(user.User.id == user_id).first()
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(password_change.current_password, user_obj.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect current password")

    user_obj.password_hash = hash_password(password_change.new_password)
    db.commit()
    return {"msg": "Password changed successfully"}

@router.post("/enable-2fa", response_model=dict)
def enable_2fa(enable_2fa: Enable2FA, user_id: int, db: Session = Depends(get_db)):
    user_obj = db.query(user.User).filter(user.User.id == user_id).first()
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(enable_2fa.password, user_obj.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect password")

    if user_obj.totp_secret:
        raise HTTPException(status_code=400, detail="2FA is already enabled")

    totp_secret = generate_totp()
    user_obj.totp_secret = totp_secret
    db.commit()

    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(user_obj.email, issuer_name="SecureChat")

    return {
        "msg": "2FA enabled successfully",
        "secret": totp_secret,
        "qr_code_uri": provisioning_uri
    }

@router.post("/disable-2fa", response_model=dict)
def disable_2fa(disable_2fa: Disable2FA, user_id: int, db: Session = Depends(get_db)):
    user_obj = db.query(user.User).filter(user.User.id == user_id).first()
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(disable_2fa.password, user_obj.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect password")

    if not user_obj.totp_secret:
        raise HTTPException(status_code=400, detail="2FA is not enabled")

    totp = pyotp.TOTP(user_obj.totp_secret)
    if not totp.verify(disable_2fa.totp_code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    user_obj.totp_secret = None
    db.commit()
    return {"msg": "2FA disabled successfully"}

@router.post("/update-ms-id", response_model=dict)
def update_ms_id(user_id: int, db: Session = Depends(get_db)):
    user_obj = db.query(user.User).filter(user.User.id == user_id).first()
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")

    new_ms_id = str(uuid.uuid4())
    user_obj.ms_id = new_ms_id
    db.commit()
    return {"msg": "ms_id updated successfully", "new_ms_id": new_ms_id}

@router.post("/upload-avatar")
async def upload_avatar(file: UploadFile = File(...), user_id: int = Query(...), db: Session = Depends(get_db)):
    user_obj = db.query(user.User).filter(user.User.id == user_id).first()
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")

    # Implement avatar upload logic here
    # You may want to use the media upload functionality from the media.py file

    return {"msg": "Avatar uploaded successfully"}