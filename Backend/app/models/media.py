from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func, LargeBinary
from app.db.connection import Base

class Media(Base):
    __tablename__ = 'media'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    filename = Column(String, nullable=False)
    mime_type = Column(String, nullable=False)
    size = Column(Integer, nullable=False)
    encrypted_content = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    message_id = Column(Integer, ForeignKey('messages.id'), nullable=True)