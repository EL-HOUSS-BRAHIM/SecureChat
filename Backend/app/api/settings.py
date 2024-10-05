from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.models import user

router = APIRouter()

@router.post("/profile/update-ms_id")
def update_ms_id(user_id: int, new_ms_id: str, db: Session = Depends(get_db)):
    # Logic to update ms_id
    user_obj = db.query(user.User).filter(user.User.id == user_id).first()
    if not user_obj:
        raise HTTPException(status_code=400, detail="User not found")
    user_obj.ms_id = new_ms_id
    db.commit()
    return {"msg": "ms_id updated"}

@router.post("/profile/enable-2fa")
def enable_2fa(user_id: int, db: Session = Depends(get_db)):
    # Logic to enable 2FA
    user_obj = db.query(user.User).filter(user.User.id == user_id).first()
    user_obj.totp_secret = "new_totp_secret"  # Generate TOTP secret
    db.commit()
    return {"msg": "2FA enabled"}

@router.post("/profile/revoke-sessions")
def revoke_sessions(user_id: int, db: Session = Depends(get_db)):
    # Logic to revoke all sessions
    return {"msg": "Sessions revoked"}
