# tests/test_auth.py
import pytest
from app.models.user import User
from app.services.session_manager import SessionManager

def test_register_user(client, test_db):
    # Mock user registration data
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "strongpassword123",
        "ms_id": "unique_ms_id"
    }

    response = client.post("/auth/register", json=user_data)
    assert response.status_code == 200
    assert response.json()["msg"] == "Registration successful"

def test_login_user(client, test_db):
    login_data = {
        "username": "testuser",
        "password": "strongpassword123"
    }

    response = client.post("/auth/login", json=login_data)
    assert response.status_code == 200
    assert "access_token" in response.json()
