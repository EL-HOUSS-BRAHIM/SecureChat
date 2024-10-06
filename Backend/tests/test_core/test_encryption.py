# tests/test_core/test_encryption.py
import pytest
import base64
import os
from app.core.encryption import encrypt_message, decrypt_message, encrypt_image

def test_encrypt_decrypt_message():
    original_message = "Hello, World!"
    public_key = base64.urlsafe_b64encode(os.urandom(32))
    private_key = "mock_private_key"
    
    encrypted_message = encrypt_message(original_message, public_key)
    decrypted_message = decrypt_message(encrypted_message, private_key)
    
    assert decrypted_message == original_message
    assert encrypted_message != original_message

def test_encrypt_image():
    with open("tests/test_data/test_image.jpg", "rb") as image_file:
        image_data = image_file.read()
    
    encrypted_image = encrypt_image(image_data, "mock_symmetric_key")
    
    assert encrypted_image != image_data
    assert len(encrypted_image) > 0