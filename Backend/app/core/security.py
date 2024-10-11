import pyotp
import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import secrets
import jwt
from datetime import datetime, timedelta
import random  # For generating OTP
from app.services.email_service import send_verification_email

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
    totp = pyotp.TOTP(pyotp.random_base32())
    return totp.provisioning_uri(name="YourApp", issuer_name="YourCompany")

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
