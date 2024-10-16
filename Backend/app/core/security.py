import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import random  # For generating OTP
from app.services.email_service import send_verification_email
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import Optional
import pyotp
from fastapi import HTTPException, Depends, status
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None
    
def verify_ws_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")


# Update these with secure values
SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM')
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES')

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        if username is None or user_id is None:
            raise credentials_exception
        token_data = TokenData(username=username, user_id=user_id)
        return token_data
    except JWTError:
        raise credentials_exception


# Function to generate a new RSA private key
def generate_private_key() -> str:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # No encryption
    )

    return pem.decode('utf-8')  # Return the PEM as a string

# Function to generate a public key from a private key
def generate_public_key(private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem.decode('utf-8')  # Return as string for storage

# Function to generate a TOTP secret
def generate_totp() -> str:
    return pyotp.random_base32()

# Function to verify the provided TOTP code
def verify_totp(secret: str, totp_code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(totp_code)

# Function to hash a password
def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')

# Function to verify a hashed password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# Function to generate a verification token (JWT)
def generate_verification_token(email: str, secret_key: str, expiration: int = 3600) -> str:
    payload = {
        "email": email,
        "exp": datetime.utcnow() + timedelta(seconds=expiration)
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")

# Function to verify the verification token
def verify_verification_token(token: str, secret_key: str) -> dict:
    try:
        return jwt.decode(token, secret_key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

# Function to generate a 6-digit OTP for email verification
def generate_otp() -> str:
    return str(random.randint(100000, 999999))

# Function to send OTP via email
def send_otp_email(email: str, otp: str):
    # Assuming send_verification_email is implemented in email_service.py
    message = f"Your login OTP code is: {otp}"
    send_verification_email(email, message)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    return verify_token(token)
