# tests/test_api/test_settings.py
import pytest
from fastapi.testclient import TestClient
from app.api.settings import router as settings_router

def test_update_ms_id(client, mock_db):
    response = client.post("/profile/update-ms_id", json={
        "new_ms_id": "new_unique_ms_id"
    }, headers={"Authorization": "Bearer mock_token"})
    assert response.status_code == 200
    assert "message" in response.json()
    assert "MS ID updated successfully" in response.json()["message"]

def test_enable_2fa(client, mock_db):
    response = client.post("/profile/enable-2fa", headers={"Authorization": "Bearer mock_token"})
    assert response.status_code == 200
    assert "totp_secret" in response.json()
    assert "qr_code" in response.json()

def test_revoke_sessions(client, mock_db):
    response = client.post("/profile/revoke-sessions", headers={"Authorization": "Bearer mock_token"})
    assert response.status_code == 200
    assert "message" in response.json()
    assert "All sessions revoked" in response.json()["message"]