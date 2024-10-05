from sqlalchemy import Column, String, Boolean, Integer, DateTime, func
from app.db.connection import Base

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(100), nullable=False)
    ms_id = Column(String(100), unique=True, nullable=False)  # Editable Message ID
    public_key = Column(String, nullable=False)
    private_key = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    totp_secret = Column(String(100), nullable=True)  # TOTP secret for 2FA
    created_at = Column(DateTime(timezone=True), server_default=func.now())
