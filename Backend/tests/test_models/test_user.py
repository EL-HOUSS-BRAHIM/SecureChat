# tests/test_models/test_user.py
import pytest
from app.models.user import User

def test_user_creation():
    user = User(
        username="testuser",
        email="test@example.com",
        password="hashed_password",
        ms_id="unique_ms_id",
        public_key="user_public_key"
    )
    assert user.username == "testuser"
    assert user.email == "test@example.com"
    assert user.ms_id == "unique_ms_id"
    assert user.public_key == "user_public_key"
    assert user.is_2fa_enabled == False