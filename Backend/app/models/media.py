from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func
from app.db.connection import Base

class Media(Base):
    __tablename__ = 'media'

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey('messages.id'), nullable=False)
    encrypted_file_path = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
