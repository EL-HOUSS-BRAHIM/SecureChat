# tests/test_core/test_websockets.py
import pytest
from fastapi.testclient import TestClient
from app.main import app  # Import the main FastAPI app instead

def test_websocket_connection(client):
    with client.websocket_connect("/ws") as websocket:
        data = websocket.receive_json()
        assert "message" in data
        assert data["message"] == "Connected to WebSocket"

def test_websocket_message(client):
    with client.websocket_connect("/ws") as websocket:
        websocket.send_json({"message": "Hello, WebSocket!"})
        data = websocket.receive_json()
        assert "message" in data
        assert data["message"] == "Message received: Hello, WebSocket!"
