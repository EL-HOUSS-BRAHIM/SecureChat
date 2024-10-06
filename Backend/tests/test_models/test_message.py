# tests/test_models/test_message.py
import pytest
from app.models.message import Message

def test_message_creation():
    message = Message(
        sender_id=1,
        recipient_id=2,
        encrypted_content="encrypted_message_data"
    )
    assert message.sender_id == 1
    assert message.recipient_id == 2
    assert message.encrypted_content == "encrypted_message_data"