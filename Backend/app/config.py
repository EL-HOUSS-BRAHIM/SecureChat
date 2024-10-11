import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    DATABASE_URL = os.getenv('DATABASE_URL')
    TOTP_SECRET_KEY = os.getenv('TOTP_SECRET_KEY')
    MEDIA_FOLDER = os.getenv('MEDIA_FOLDER')  # Default value if not set
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')

    @staticmethod
    def init_app(app):
        # Validate required environment variables
        required_vars = ['SECRET_KEY', 'DATABASE_URL', 'TOTP_SECRET_KEY', 'ENCRYPTION_KEY']
        missing_vars = [var for var in required_vars if os.getenv(var) is None]

        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")