from cryptography.fernet import Fernet

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
