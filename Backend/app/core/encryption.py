from cryptography.fernet import Fernet
import os
from io import BytesIO

def encrypt_message(content: str, public_key: str) -> str:
    # Logic to encrypt a message using a public key
    return Fernet(public_key).encrypt(content.encode())

def decrypt_message(encrypted_content: str, private_key: str) -> str:
    # Logic to decrypt a message using a private key
    return Fernet(private_key).decrypt(encrypted_content.encode()).decode()

def encrypt_image(image_file) -> bytes:
    # Logic to encrypt image file
    return Fernet.generate_key().encrypt(image_file.read())

def decrypt_image(encrypted_image: bytes) -> bytes:
    # Logic to decrypt image file
    return Fernet.generate_key().decrypt(encrypted_image)

ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

def encrypt_file(file_content: bytes) -> bytes:
    """
    Encrypts the given file content.
    
    :param file_content: The content of the file as bytes
    :return: Encrypted content as bytes
    """
    return fernet.encrypt(file_content)

def decrypt_file(encrypted_content: bytes) -> bytes:
    """
    Decrypts the given encrypted content.
    
    :param encrypted_content: The encrypted content as bytes
    :return: Decrypted content as bytes
    """
    return fernet.decrypt(encrypted_content)

# Helper functions to work with file-like objects
def encrypt_file_object(file_object):
    """
    Encrypts the content of a file-like object.
    
    :param file_object: A file-like object (e.g., BytesIO, File)
    :return: BytesIO object containing the encrypted content
    """
    file_content = file_object.read()
    encrypted_content = encrypt_file(file_content)
    return BytesIO(encrypted_content)

def decrypt_file_object(encrypted_file_object):
    """
    Decrypts the content of an encrypted file-like object.
    
    :param encrypted_file_object: A file-like object containing encrypted content
    :return: BytesIO object containing the decrypted content
    """
    encrypted_content = encrypted_file_object.read()
    decrypted_content = decrypt_file(encrypted_content)
    return BytesIO(decrypted_content)