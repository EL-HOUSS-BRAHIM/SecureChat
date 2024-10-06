# tests/test_api/test_auth.py
import pytest
from fastapi.testclient import TestClient
from app.api.auth import router as auth_router
from app.core.security import generate_totp, verify_totp

def test_register(client, mock_db):
    response = client.post("/register", json={
        "username": "testuser",
        "password": "testpassword",
        "email": "test@example.com"
    })
    assert response.status_code == 201
    assert "ms_id" in response.json()
    assert "public_key" in response.json()

def test_login(client, mock_db):
    # Mock user in database
    mock_db.return_value.query.return_value.filter.return_value.first.return_value = {
        "id": 1,
        "username": "testuser",
        "password": "hashed_password",
        "totp_secret": "mocked_totp_secret"
    }
    
    response = client.post("/login", json={
        "username": "testuser",
        "password": "testpassword"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_login_with_2fa(client, mock_db):
    # Mock user in database with 2FA enabled
    mock_user = {
        "id": 1,
        "username": "testuser",
        "password": "hashed_password",
        "totp_secret": "mocked_totp_secret",
        "is_2fa_enabled": True
    }
    mock_db.return_value.query.return_value.filter.return_value.first.return_value = mock_user
    
    # First step: login without 2FA code
    response = client.post("/login", json={
        "username": "testuser",
        "password": "testpassword"
    })
    assert response.status_code == 202
    assert "message" in response.json()
    assert "2FA required" in response.json()["message"]
    
    # Second step: provide 2FA code
    totp_code = generate_totp(mock_user["totp_secret"])
    response = client.post("/login/2fa", json={
        "username": "testuser",
        "totp_code": totp_code
    })
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_logout(client, mock_db):
    response = client.post("/logout", headers={"Authorization": "Bearer mock_token"})
    assert response.status_code == 200
    assert "message" in response.json()
    assert "Logged out successfully" in response.json()["message"]