# tests/test_models/test_friend.py
import pytest
from app.models.friend import FriendRequest  # Adjust this import based on your actual model name

def test_friend_request_creation():
    friend_request = FriendRequest(  # Use the correct model name here
        requester_id=1,
        recipient_id=2,
        status="pending"
    )
    assert friend_request.requester_id == 1
    assert friend_request.recipient_id == 2
    assert friend_request.status == "pending"
