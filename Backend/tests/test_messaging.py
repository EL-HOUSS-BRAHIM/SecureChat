# tests/test_messages.py
def test_send_message(client, test_db):
    message_data = {
        "receiver_ms_id": "friend_ms_id",
        "content": "Hello, how are you?"
    }

    response = client.websocket_send("/messages/send", json=message_data)
    assert response.status_code == 200
    assert response.json()["msg"] == "Message sent"

def test_retrieve_messages(client, test_db):
    response = client.get("/messages/retrieve?receiver_ms_id=friend_ms_id")
    assert response.status_code == 200
    assert len(response.json()) > 0
