import pytest
from fastapi.testclient import TestClient
from fastapi import WebSocket, HTTPException, FastAPI
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from cryptography.fernet import Fernet
import pyotp
from unittest.mock import Mock, patch

import sys
import os

# Add the parent directory of 'app' to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.main import app
from app.db.connection import get_db, Base
from app.models import user, friend
from app.core.security import generate_totp, verify_totp
from app.core.encryption import encrypt_message, decrypt_message, encrypt_image, decrypt_image
from app.services.email_service import send_verification_email, send_2fa_email
from app.core.websockets import WebSocketManager
from app.services.session_manager import SessionManager

# Setup SQLite in-memory test database
SQLALCHEMY_DATABASE_URL = "sqlite://"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={
                       "check_same_thread": False}, poolclass=StaticPool)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

# Setup FastAPI test client
client = TestClient(app)

# Fixtures for database and session management


@pytest.fixture
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def mock_db(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def session_manager():
    return SessionManager()

# Auth Tests


def test_user_registration(mock_db):
    response = client.post(
        "/auth/register", json={"username": "testuser", "email": "test@example.com", "password": "password123"})
    assert response.status_code == 200, f"Registration failed with status code {
        response.status_code}"
    assert response.json() == {
        "msg": "User registered successfully"}, "Unexpected response message"
    print("User registration test passed successfully")


def test_user_login(mock_db):
    client.post("/auth/register", json={"username": "testuser",
                "email": "test@example.com", "password": "password123"})
    response = client.post(
        "/login", json={"email": "test@example.com", "password": "password123", "totp_code": ""})
    assert response.status_code == 200, f"Login failed with status code {
        response.status_code}"
    assert response.json() == {
        "msg": "Login successful"}, "Unexpected login response message"
    print("User login test passed successfully")


def test_user_logout():
    response = client.post("/logout")
    assert response.status_code == 200, f"Logout failed with status code {
        response.status_code}"
    assert response.json() == {
        "msg": "User logged out successfully"}, "Unexpected logout response message"
    print("User logout test passed successfully")

# Friends Tests


def test_send_friend_request(mock_db):
    response = client.post(
        "/friends/request", json={"requester_id": 1, "receiver_ms_id": "receiver123"})
    assert response.status_code == 200, f"Sending friend request failed with status code {
        response.status_code}"
    assert response.json() == {
        "msg": "Friend request sent"}, "Unexpected friend request response message"
    print("Send friend request test passed successfully")


def test_accept_friend_request(mock_db):
    client.post("/friends/request",
                json={"requester_id": 1, "receiver_ms_id": "receiver123"})
    response = client.post("/friends/accept", json={"request_id": 1})
    assert response.status_code == 200, f"Accepting friend request failed with status code {
        response.status_code}"
    assert response.json() == {
        "msg": "Friend request accepted"}, "Unexpected friend request acceptance response message"
    print("Accept friend request test passed successfully")

# Messages Tests


@pytest.mark.asyncio
async def test_send_message(mock_db):
    async def mock_websocket():
        return Mock(spec=WebSocket)

    websocket = await mock_websocket()
    websocket.receive_json.return_value = {
        "content": "Hello", "receiver_public_key": "dummy_key"}

    with patch("app.core.encryption.encrypt_message", return_value="encrypted_message"):
        await app.send_message(websocket)

    websocket.send_json.assert_called_with({"msg": "Message sent"})
    print("Send message test passed successfully")


def test_retrieve_messages(mock_db):
    response = client.get("/messages/retrieve?sender_id=1&receiver_id=2")
    assert response.status_code == 200, f"Retrieving messages failed with status code {
        response.status_code}"
    assert "messages" in response.json(), "Messages not found in response"
    print("Retrieve messages test passed successfully")

# Settings Tests


def test_update_ms_id(mock_db):
    client.post("/register", json={"username": "testuser",
                "email": "test@example.com", "password": "password123"})
    response = client.post("/profile/update-ms_id",
                           json={"user_id": 1, "new_ms_id": "newmsid123"})
    assert response.status_code == 200, f"Updating ms_id failed with status code {
        response.status_code}"
    assert response.json() == {
        "msg": "ms_id updated"}, "Unexpected ms_id update response message"
    print("Update ms_id test passed successfully")


def test_enable_2fa(mock_db):
    client.post("/register", json={"username": "testuser",
                "email": "test@example.com", "password": "password123"})
    response = client.post("/profile/enable-2fa", json={"user_id": 1})
    assert response.status_code == 200, f"Enabling 2FA failed with status code {
        response.status_code}"
    assert response.json() == {
        "msg": "2FA enabled"}, "Unexpected 2FA enable response message"
    print("Enable 2FA test passed successfully")

# Media Tests


def test_upload_media():
    with patch("app.core.encryption.encrypt_image", return_value=b"encrypted_image_data"):
        response = client.post(
            "/media/upload", files={"file": ("test.jpg", b"image_data", "image/jpeg")})
    assert response.status_code == 200, f"Media upload failed with status code {
        response.status_code}"
    assert response.json() == {
        "msg": "File uploaded successfully"}, "Unexpected media upload response message"
    print("Upload media test passed successfully")


def test_retrieve_media():
    with patch("app.core.encryption.decrypt_image", return_value=b"decrypted_image_data"):
        response = client.get("/media/retrieve/1")
    assert response.status_code == 200, f"Media retrieval failed with status code {
        response.status_code}"
    assert "image" in response.json(), "Image data not found in response"
    print("Retrieve media test passed successfully")

# Encryption Tests


def test_encrypt_decrypt_message():
    message = "Hello, World!"
    key = Fernet.generate_key()
    encrypted = encrypt_message(message, key)
    decrypted = decrypt_message(encrypted, key)
    assert decrypted == message, "Message encryption/decryption failed"
    print("Encrypt/decrypt message test passed successfully")


@pytest.mark.asyncio
async def test_encrypt_decrypt_image(tmp_path):
    image_content = b"fake image content"
    image_file = tmp_path / "test_image.jpg"
    image_file.write_bytes(image_content)

    with open(image_file, "rb") as f:
        encrypted = encrypt_image(f)

    decrypted = decrypt_image(encrypted)
    assert decrypted == image_content, "Image encryption/decryption failed"
    print("Encrypt/decrypt image test passed successfully")

# Security Tests


def test_generate_verify_totp():
    totp_uri = generate_totp()
    secret = pyotp.parse_uri(totp_uri).secret
    totp = pyotp.TOTP(secret)
    assert verify_totp(secret, totp.now()), "TOTP verification failed"
    print("Generate and verify TOTP test passed successfully")

# WebSocket Tests


@pytest.mark.asyncio
async def test_websocket_manager():
    manager = WebSocketManager()
    mock_websocket = Mock()
    await manager.connect(mock_websocket)
    assert mock_websocket in manager.active_connections, "WebSocket connection failed"

    test_message = "Test message"
    await manager.broadcast(test_message)
    mock_websocket.send_text.assert_called_with(test_message)

    manager.disconnect(mock_websocket)
    assert mock_websocket not in manager.active_connections, "WebSocket disconnection failed"
    print("WebSocket manager test passed successfully")

# Session Manager Tests


def test_create_session(session_manager):
    user_id = 1
    session_manager.create_session(user_id)
    assert user_id in session_manager.active_sessions, "Session creation failed"
    assert "session_token" in session_manager.active_sessions[
        user_id], "Session token not generated"
    print("Create session test passed successfully")


def test_revoke_session(session_manager):
    user_id = 1
    session_manager.create_session(user_id)
    session_manager.revoke_session(user_id)
    assert user_id not in session_manager.active_sessions, "Session revocation failed"
    print("Revoke session test passed successfully")


def test_revoke_session_not_found(session_manager):
    with pytest.raises(HTTPException) as exc_info:
        session_manager.revoke_session(999)
    assert exc_info.value.status_code == 400, "Unexpected status code for non-existent session"
    assert exc_info.value.detail == "Session not found", "Unexpected error message for non-existent session"
    print("Revoke non-existent session test passed successfully")


def test_revoke_all_sessions(session_manager):
    user_id_1 = 1
    user_id_2 = 2
    session_manager.create_session(user_id_1)
    session_manager.create_session(user_id_2)
    result = session_manager.revoke_all_sessions(user_id_1)
    assert user_id_1 not in session_manager.active_sessions, "Failed to revoke session for user 1"
    assert user_id_2 in session_manager.active_sessions, "Incorrectly revoked session for user 2"
    assert result == {
        "msg": "All sessions revoked"}, "Unexpected response message for revoking all sessions"
    print("Revoke all sessions test passed successfully")


def test_check_session_valid(session_manager):
    user_id = 1
    session_manager.create_session(user_id)
    session_token = session_manager.active_sessions[user_id]["session_token"]
    assert session_manager.check_session(
        user_id, session_token) is True, "Valid session check failed"
    print("Check valid session test passed successfully")


def test_check_session_invalid(session_manager):
    user_id = 1
    session_manager.create_session(user_id)
    with pytest.raises(HTTPException) as exc_info:
        session_manager.check_session(user_id, "invalid_token")
    assert exc_info.value.status_code == 401, "Unexpected status code for invalid session"
    assert exc_info.value.detail == "Invalid session", "Unexpected error message for invalid session"
    print("Check invalid session test passed successfully")

# Email Service Tests


@patch('smtplib.SMTP')
def test_send_verification_email(mock_smtp):
    email = "test@example.com"
    token = "test_token"
    send_verification_email(email, token)
    mock_smtp.return_value.__enter__.return_value.sendmail.assert_called()
    print("Send verification email test passed successfully")


@patch('smtplib.SMTP')
def test_send_2fa_email(mock_smtp):
    email = "test@example.com"
    totp_code = "123456"
    send_2fa_email(email, totp_code)
    mock_smtp.return_value.__enter__.return_value.sendmail.assert_called()
    print("Send 2FA email test passed successfully")

# Full Integration Tests


def test_full_user_flow(mock_db):
    # Register
    register_response = client.post(
        "/register", json={"username": "testuser", "email": "test@example.com", "password": "password123"})
    assert register_response.status_code == 200, f"Registration failed with status code {
        register_response.status_code}"
    print("User registration in full flow test passed successfully")

    # Login
    login_response = client.post(
        "/login", json={"email": "test@example.com", "password": "password123", "totp_code": ""})
    assert login_response.status_code == 200, f"Login failed with status code {
        login_response.status_code}"
    print("User login in full flow test passed successfully")

    # Enable 2FA
    enable_2fa_response = client.post(
        "/profile/enable-2fa", json={"user_id": 1})
    assert enable_2fa_response.status_code == 200, f"Enabling 2FA failed with status code {
        enable_2fa_response.status_code}"
    print("Enable 2FA in full flow test passed successfully")

    # Send friend request
    send_request_response = client.post(
        "/friends/request", json={"requester_id": 1, "receiver_ms_id": "receiver123"})
    assert send_request_response.status_code == 200, f"Sending friend request failed with status code {
        send_request_response.status_code}"
    print("Send friend request in full flow test passed successfully")

    # Accept friend request
    accept_request_response = client.post(
        "/friends/accept", json={"request_id": 1})
    assert accept_request_response.status_code == 200, f"Accepting friend request failed with status code {
        accept_request_response.status_code}"
    print("Accept friend request in full flow test passed successfully")

    # Upload and retrieve media
    with patch("app.core.encryption.encrypt_image", return_value=b"encrypted_image_data"):
        upload_media_response = client.post(
            "/media/upload", files={"file": ("test.jpg", b"image_data", "image/jpeg")})
    assert upload_media_response.status_code == 200, f"Media upload failed with status code {
        upload_media_response.status_code}"
    print("Upload media in full flow test passed successfully")

    with patch("app.core.encryption.decrypt_image", return_value=b"decrypted_image_data"):
        retrieve_media_response = client.get("/media/retrieve/1")
    assert retrieve_media_response.status_code == 200, f"Media retrieval failed with status code {
        retrieve_media_response.status_code}"
    print("Retrieve media in full flow test passed successfully")

    print("Full user flow test completed successfully")

# Additional error handling and edge cases


def test_registration_with_existing_email(mock_db):
    # Register first user
    client.post("/register", json={"username": "testuser1",
                "email": "test@example.com", "password": "password123"})

    # Try to register second user with same email
    response = client.post(
        "/register", json={"username": "testuser2", "email": "test@example.com", "password": "password456"})
    assert response.status_code == 400, f"Expected 400 status code, but got {
        response.status_code}"
    assert "Email already registered" in response.json(
    )["detail"], "Unexpected error message for duplicate email registration"
    print("Registration with existing email test passed successfully")


def test_login_with_incorrect_password(mock_db):
    # Register user
    client.post("/register", json={"username": "testuser",
                "email": "test@example.com", "password": "password123"})

    # Attempt login with incorrect password
    response = client.post(
        "/login", json={"email": "test@example.com", "password": "wrongpassword", "totp_code": ""})
    assert response.status_code == 401, f"Expected 401 status code, but got {
        response.status_code}"
    assert "Incorrect email or password" in response.json(
    )["detail"], "Unexpected error message for incorrect password"
    print("Login with incorrect password test passed successfully")


def test_friend_request_to_non_existent_user(mock_db):
    # Register user
    client.post("/register", json={"username": "testuser",
                "email": "test@example.com", "password": "password123"})

    # Send friend request to non-existent user
    response = client.post(
        "/friends/request", json={"requester_id": 1, "receiver_ms_id": "non_existent_user"})
    assert response.status_code == 404, f"Expected 404 status code, but got {
        response.status_code}"
    assert "User not found" in response.json(
    )["detail"], "Unexpected error message for friend request to non-existent user"
    print("Friend request to non-existent user test passed successfully")


def test_accept_non_existent_friend_request(mock_db):
    # Register user
    client.post("/register", json={"username": "testuser",
                "email": "test@example.com", "password": "password123"})

    # Try to accept non-existent friend request
    response = client.post("/friends/accept", json={"request_id": 999})
    assert response.status_code == 404, f"Expected 404 status code, but got {
        response.status_code}"
    assert "Friend request not found" in response.json(
    )["detail"], "Unexpected error message for accepting non-existent friend request"
    print("Accept non-existent friend request test passed successfully")


@pytest.mark.asyncio
async def test_send_message_to_non_friend(mock_db):
    async def mock_websocket():
        return Mock(spec=WebSocket)

    websocket = await mock_websocket()
    websocket.receive_json.return_value = {
        "content": "Hello", "receiver_public_key": "dummy_key", "receiver_id": 999}

    with pytest.raises(HTTPException) as exc_info:
        await app.send_message(websocket)

    assert exc_info.value.status_code == 403, f"Expected 403 status code, but got {
        exc_info.value.status_code}"
    assert "Cannot send message to non-friend" in str(
        exc_info.value.detail), "Unexpected error message for sending message to non-friend"
    print("Send message to non-friend test passed successfully")


def test_retrieve_messages_with_invalid_ids(mock_db):
    response = client.get("/messages/retrieve?sender_id=999&receiver_id=998")
    assert response.status_code == 404, f"Expected 404 status code, but got {
        response.status_code}"
    assert "No messages found" in response.json(
    )["detail"], "Unexpected error message for retrieving messages with invalid IDs"
    print("Retrieve messages with invalid IDs test passed successfully")


def test_update_ms_id_for_non_existent_user(mock_db):
    response = client.post("/profile/update-ms_id",
                           json={"user_id": 999, "new_ms_id": "newmsid123"})
    assert response.status_code == 404, f"Expected 404 status code, but got {
        response.status_code}"
    assert "User not found" in response.json(
    )["detail"], "Unexpected error message for updating ms_id of non-existent user"
    print("Update ms_id for non-existent user test passed successfully")


def test_enable_2fa_for_non_existent_user(mock_db):
    response = client.post("/profile/enable-2fa", json={"user_id": 999})
    assert response.status_code == 404, f"Expected 404 status code, but got {
        response.status_code}"
    assert "User not found" in response.json(
    )["detail"], "Unexpected error message for enabling 2FA for non-existent user"
    print("Enable 2FA for non-existent user test passed successfully")


def test_upload_invalid_media_type():
    response = client.post(
        "/media/upload", files={"file": ("test.txt", b"text data", "text/plain")})
    assert response.status_code == 400, f"Expected 400 status code, but got {
        response.status_code}"
    assert "Invalid file type" in response.json(
    )["detail"], "Unexpected error message for uploading invalid media type"
    print("Upload invalid media type test passed successfully")


def test_retrieve_non_existent_media():
    response = client.get("/media/retrieve/999")
    assert response.status_code == 404, f"Expected 404 status code, but got {
        response.status_code}"
    assert "Media not found" in response.json(
    )["detail"], "Unexpected error message for retrieving non-existent media"
    print("Retrieve non-existent media test passed successfully")


def test_encrypt_decrypt_message_mismatch():
    message = "Hello, World!"
    key1 = Fernet.generate_key()
    key2 = Fernet.generate_key()
    encrypted = encrypt_message(message, key1)
    with pytest.raises(Exception) as exc_info:
        decrypt_message(encrypted, key2)
    assert "Decryption failed" in str(
        exc_info.value), "Unexpected error message for decryption with mismatched key"
    print("Encrypt/decrypt message mismatch test passed successfully")


def test_invalid_totp():
    totp_uri = generate_totp()
    secret = pyotp.parse_uri(totp_uri).secret
    invalid_totp = "000000"  # Assuming this is an invalid TOTP
    assert not verify_totp(
        secret, invalid_totp), "Invalid TOTP should not be verified"
    print("Invalid TOTP test passed successfully")


@pytest.mark.asyncio
async def test_websocket_disconnect_handling():
    manager = WebSocketManager()
    mock_websocket = Mock()
    await manager.connect(mock_websocket)
    manager.disconnect(mock_websocket)
    assert len(
        manager.active_connections) == 0, "WebSocket connection not properly removed after disconnection"
    print("WebSocket disconnect handling test passed successfully")


def test_session_expiration(session_manager):
    user_id = 1
    session_manager.create_session(user_id)
    session_token = session_manager.active_sessions[user_id]["session_token"]

    # Simulate session expiration
    session_manager.active_sessions[user_id]["expiry"] = 0

    with pytest.raises(HTTPException) as exc_info:
        session_manager.check_session(user_id, session_token)
    assert exc_info.value.status_code == 401, f"Expected 401 status code, but got {
        exc_info.value.status_code}"
    assert "Session expired" in str(
        exc_info.value.detail), "Unexpected error message for expired session"
    print("Session expiration test passed successfully")


@patch('smtplib.SMTP')
def test_email_service_failure(mock_smtp):
    mock_smtp.return_value.__enter__.return_value.sendmail.side_effect = Exception(
        "SMTP error")

    with pytest.raises(Exception) as exc_info:
        send_verification_email("test@example.com", "test_token")
    assert "Failed to send email" in str(
        exc_info.value), "Unexpected error message for email service failure"
    print("Email service failure test passed successfully")


def test_full_user_flow_with_2fa(mock_db):
    # Register
    register_response = client.post(
        "/register", json={"username": "testuser", "email": "test@example.com", "password": "password123"})
    assert register_response.status_code == 200, f"Registration failed with status code {
        register_response.status_code}"
    print("User registration in full flow with 2FA test passed successfully")

    # Enable 2FA
    enable_2fa_response = client.post(
        "/profile/enable-2fa", json={"user_id": 1})
    assert enable_2fa_response.status_code == 200, f"Enabling 2FA failed with status code {
        enable_2fa_response.status_code}"
    print("Enable 2FA in full flow with 2FA test passed successfully")

    # Login attempt without 2FA code
    login_response_no_2fa = client.post(
        "/login", json={"email": "test@example.com", "password": "password123", "totp_code": ""})
    assert login_response_no_2fa.status_code == 401, f"Expected 401 status code for login without 2FA, but got {
        login_response_no_2fa.status_code}"
    print("Login attempt without 2FA code test passed successfully")

    # Login with 2FA code
    with patch("app.core.security.verify_totp", return_value=True):
        login_response_with_2fa = client.post(
            "/login", json={"email": "test@example.com", "password": "password123", "totp_code": "123456"})
    assert login_response_with_2fa.status_code == 200, f"Login with 2FA failed with status code {
        login_response_with_2fa.status_code}"
    print("Login with 2FA code test passed successfully")

    print("Full user flow with 2FA test completed successfully")


# Run all tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
