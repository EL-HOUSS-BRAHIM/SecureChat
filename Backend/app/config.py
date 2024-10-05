import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_default_secret_key')
    DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://user:password@localhost/dbname')
    TOTP_SECRET_KEY = os.getenv('TOTP_SECRET_KEY', 'your_totp_secret_key')  # Use this key to generate 2FA TOTP secrets
    MEDIA_FOLDER = os.getenv('MEDIA_FOLDER', 'media/')
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', 'default_encryption_key')  # Encryption key for media

    @staticmethod
    def init_app(app):
        pass
