from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.models import user
from app.core.security import (
    send_otp_email, generate_otp, generate_totp, verify_totp, 
    hash_password, generate_private_key, generate_public_key, 
    verify_password, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
)
from app.services.email_service import send_verification_email
from app.db.otp_service import OTPService
from datetime import timedelta
import uuid

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    totp_code: str = None

class Token(BaseModel):
    access_token: str
    token_type: str

class UserRegistration(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserOTPVerification(BaseModel):
    email: EmailStr
    otp: str

class PasswordReset(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    email: EmailStr
    reset_token: str
    new_password: str

@router.post("/register", response_model=dict)
async def register_user(user_data: UserRegistration, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if db.query(user.User).filter(user.User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(user_data.password)
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    ms_id = str(uuid.uuid4())

    new_user = user.User(
        username=user_data.username,
        email=user_data.email,
        password_hash=hashed_password,
        ms_id=ms_id,
        public_key=public_key,
        private_key=private_key
    )

    db.add(new_user)
    db.commit()
    
    background_tasks.add_task(send_verification_email, user_data.email)
    return {"msg": "User registered successfully. Please check your email for verification."}

@router.post("/login", response_model=Token)
async def login(response: Response, user_data: UserLogin, db: Session = Depends(get_db)):
    user_obj = db.query(user.User).filter(user.User.email == user_data.email).first()
    if not user_obj or not verify_password(user_data.password, user_obj.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    # Check TOTP if it's enabled for the user
    if user_obj.totp_secret:
        if not user_data.totp_code:
            raise HTTPException(status_code=400, detail="TOTP code required")
        if not verify_totp(user_obj.totp_secret, user_data.totp_code):
            raise HTTPException(status_code=400, detail="Invalid TOTP code")

    access_token = create_access_token(
        data={"sub": user_obj.email, "user_id": user_obj.id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    # Set cookie
    response.set_cookie(
        key="access_token", 
        value=f"Bearer {access_token}", 
        httponly=True, 
        max_age=1800, 
        expires=1800,
        samesite='lax',
        secure=True  # set to True if using HTTPS
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/verify-otp", response_model=Token)
async def verify_otp(otp_data: UserOTPVerification, db: Session = Depends(get_db)):
    user_obj = db.query(user.User).filter(user.User.email == otp_data.email).first()

    if not user_obj:
        raise HTTPException(status_code=400, detail="User not found")

    otp_token = OTPService.get_otp(db, otp_data.email)

    if not otp_token or otp_token.otp != otp_data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    OTPService.clear_otp(db, otp_data.email)

    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(data={"sub": user_obj.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/logout")
def logout_user(token: str = Depends(oauth2_scheme)):
    # Implement token blacklisting or short-lived tokens for proper logout
    return {"msg": "User logged out successfully"}

@router.post("/password-reset", response_model=dict)
async def request_password_reset(reset_data: PasswordReset, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    user_obj = db.query(user.User).filter(user.User.email == reset_data.email).first()
    if not user_obj:
        raise HTTPException(status_code=400, detail="Email not found")

    reset_token = generate_otp()
    OTPService.store_otp(db, reset_data.email, reset_token)
    
    background_tasks.add_task(send_otp_email, reset_data.email, reset_token)
    return {"msg": "Password reset instructions sent to your email"}

@router.post("/password-reset/confirm", response_model=dict)
async def confirm_password_reset(reset_data: PasswordResetConfirm, db: Session = Depends(get_db)):
    user_obj = db.query(user.User).filter(user.User.email == reset_data.email).first()
    if not user_obj:
        raise HTTPException(status_code=400, detail="User not found")

    otp_token = OTPService.get_otp(db, reset_data.email)
    if not otp_token or otp_token.otp != reset_data.reset_token:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user_obj.password_hash = hash_password(reset_data.new_password)
    db.commit()

    OTPService.clear_otp(db, reset_data.email)
    return {"msg": "Password reset successfully"}