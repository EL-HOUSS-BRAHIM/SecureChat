from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func
from app.db.connection import Base

class Message(Base):
    __tablename__ = 'messages'

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    receiver_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    encrypted_content = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
