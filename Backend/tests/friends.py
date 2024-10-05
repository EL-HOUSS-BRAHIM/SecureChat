# tests/test_friends.py
def test_send_friend_request(client, test_db):
    friend_request_data = {
        "ms_id": "friend_ms_id"
    }

    response = client.post("/friends/request", json=friend_request_data)
    assert response.status_code == 200
    assert response.json()["msg"] == "Friend request sent"

def test_accept_friend_request(client, test_db):
    accept_data = {
        "ms_id": "friend_ms_id"
    }

    response = client.post("/friends/accept", json=accept_data)
    assert response.status_code == 200
    assert response.json()["msg"] == "Friend request accepted"
