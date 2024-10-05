# tests/test_encryption.py
from app.core.encryption import encrypt_message, decrypt_message

def test_message_encryption():
    public_key = "test_public_key"
    private_key = "test_private_key"
    original_message = "Hello, this is a secret message!"

    encrypted_message = encrypt_message(original_message, public_key)
    decrypted_message = decrypt_message(encrypted_message, private_key)

    assert decrypted_message == original_message
