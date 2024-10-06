# tests/test_api/test_friends.py
import pytest
from fastapi.testclient import TestClient
from app.api.friends import router as friends_router

def test_send_friend_request(client, mock_db):
    response = client.post("/friends/request", json={
        "ms_id": "friend_ms_id"
    }, headers={"Authorization": "Bearer mock_token"})
    assert response.status_code == 201
    assert "message" in response.json()
    assert "Friend request sent" in response.json()["message"]

def test_accept_friend_request(client, mock_db):
    response = client.post("/friends/accept", json={
        "request_id": 1
    }, headers={"Authorization": "Bearer mock_token"})
    assert response.status_code == 200
    assert "message" in response.json()
    assert "Friend request accepted" in response.json()["message"]

def test_list_friends(client, mock_db):
    mock_friends = [
        {"ms_id": "friend1", "username": "Friend One", "status": "online"},
        {"ms_id": "friend2", "username": "Friend Two", "status": "offline"}
    ]
    mock_db.return_value.query.return_value.filter.return_value.all.return_value = mock_friends
    
    response = client.get("/friends/list", headers={"Authorization": "Bearer mock_token"})
    assert response.status_code == 200
    assert len(response.json()) == 2
    assert "ms_id" in response.json()[0]
    assert "status" in response.json()[0]