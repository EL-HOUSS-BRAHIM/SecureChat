# tests/test_api/test_media.py
import pytest
from fastapi.testclient import TestClient
from app.api.media import router as media_router

def test_upload_media(client, mock_db):
    with open("tests/test_data/test_image.jpg", "rb") as image_file:
        response = client.post("/media/upload", 
                               files={"file": ("test_image.jpg", image_file, "image/jpeg")},
                               headers={"Authorization": "Bearer mock_token"})
    assert response.status_code == 201
    assert "media_id" in response.json()

def test_retrieve_media(client, mock_db):
    mock_media = {
        "id": 1,
        "encrypted_content": b"encrypted_image_data"
    }
    mock_db.return_value.query.return_value.filter.return_value.first.return_value = mock_media
    
    response = client.get("/media/retrieve/1", headers={"Authorization": "Bearer mock_token"})
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/octet-stream"
    assert len(response.content) > 0