# tests/test_settings.py
def test_update_ms_id(client, test_db):
    update_data = {
        "new_ms_id": "new_unique_ms_id"
    }

    response = client.post("/settings/profile/update-ms_id", json=update_data)
    assert response.status_code == 200
    assert response.json()["msg"] == "ms_id updated successfully"
