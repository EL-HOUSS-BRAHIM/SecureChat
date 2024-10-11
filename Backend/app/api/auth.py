from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.models import user
from app.core.security import send_otp_email, generate_otp, generate_totp, verify_totp, hash_password, generate_private_key, generate_public_key, verify_password
from app.services.email_service import send_verification_email
import uuid  # Import UUID module to generate unique IDs
from app.db.otp_service import OTPService

router = APIRouter()

# Pydantic models
class UserRegistration(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str
    totp_code: str

class UserOTPVerification(BaseModel):
    email: str
    otp: str


@router.post("/register")
async def register_user(user_data: UserRegistration, db: Session = Depends(get_db)):
    if db.query(user.User).filter(user.User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash the password before saving
    hashed_password = hash_password(user_data.password)

    # Generate keys
    private_key = generate_private_key()  # Generate the private key
    public_key = generate_public_key(private_key)  # Pass the private key to generate the public key

    # Generate ms_id
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
    send_verification_email(user_data.email)
    return {"msg": "User registered successfully"}




@router.post("/login")
async def login_user(user_data: UserLogin, db: Session = Depends(get_db)):
    user_obj = db.query(user.User).filter(user.User.email == user_data.email).first()

    if not user_obj:
        raise HTTPException(status_code=400, detail="User not found")

    if not verify_password(user_data.password, user_obj.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if user_obj.totp_secret:
        if not verify_totp(user_obj.totp_secret, user_data.totp_code):
            raise HTTPException(status_code=400, detail="Invalid TOTP code")
        return {"msg": "Login successful with 2FA"}

    otp = generate_otp()
    OTPService.store_otp(db, user_obj.email, otp)  # Store the OTP using the OTP service
    send_otp_email(user_obj.email, otp)
    return {"msg": "OTP sent to your email", "otp_required": True}

@router.post("/verify-otp")
async def verify_otp(otp_data: UserOTPVerification, db: Session = Depends(get_db)):
    user_obj = db.query(user.User).filter(user.User.email == otp_data.email).first()

    if not user_obj:
        raise HTTPException(status_code=400, detail="User not found")

    otp_token = OTPService.get_otp(db, otp_data.email)  # Get the stored OTP

    if not otp_token or otp_token.otp != otp_data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    OTPService.clear_otp(db, otp_data.email)  # Clear OTP after successful verification
    return {"msg": "Login successful with OTP"}

@router.post("/logout")
def logout_user():
    # Terminate session logic
    return {"msg": "User logged out successfully"}
