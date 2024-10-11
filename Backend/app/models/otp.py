from sqlalchemy import Column, String, Integer, DateTime, func
from app.db.connection import Base

class OTPToken(Base):
    __tablename__ = 'otp_tokens'

    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False)
    otp = Column(String(6), nullable=False)  # Assuming a 6-digit OTP
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<OTPToken(email={self.email}, otp={self.otp}, created_at={self.created_at})>"
