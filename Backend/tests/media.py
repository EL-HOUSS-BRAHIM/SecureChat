# tests/test_media.py
def test_upload_image(client, test_db):
    files = {'file': ('test_image.png', open('tests/test_image.png', 'rb'))}
    response = client.post("/media/upload", files=files)
    assert response.status_code == 200
    assert response.json()["msg"] == "Image uploaded successfully"

def test_retrieve_image(client, test_db):
    response = client.get("/media/retrieve/1")
    assert response.status_code == 200
    assert "image" in response.content_type
