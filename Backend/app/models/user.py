from sqlalchemy import Column, String, Boolean, Integer, DateTime, func
from app.db.connection import Base

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    ms_id = Column(String, unique=True, nullable=False)
    public_key = Column(String, nullable=False)
    private_key = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    totp_secret = Column(String(100), nullable=True)  # TOTP secret for 2FA
    created_at = Column(DateTime(timezone=True), server_default=func.now())
