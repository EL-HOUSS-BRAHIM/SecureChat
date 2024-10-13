from io import BytesIO
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidKey  # Import InvalidKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

def load_public_key(pem_key: str):
    return load_pem_public_key(pem_key.encode(), backend=default_backend())

def load_private_key(pem_key: str):
    return load_pem_private_key(pem_key.encode(), password=None, backend=default_backend())

def encrypt_message(message: str, public_key: str) -> str:
    key = load_public_key(public_key)
    encrypted = key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted_message: str, private_key: str) -> str:
    key = load_private_key(private_key)
    decrypted = key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def encrypt_binary_data(binary_data: bytes, public_key_pem: str) -> bytes:
    public_key = load_public_key(public_key_pem)
    chunk_size = 190  # RSA-2048 can encrypt up to 245 bytes, but we'll use a safer size
    encrypted_chunks = []

    for i in range(0, len(binary_data), chunk_size):
        chunk = binary_data[i:i+chunk_size]
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(encrypted_chunk)

    return b''.join(encrypted_chunks)

def decrypt_binary_data(encrypted_data: bytes, private_key_pem: str) -> bytes:
    private_key = load_private_key(private_key_pem)
    chunk_size = 256  # Size of encrypted chunk for RSA-2048
    decrypted_chunks = []

    for i in range(0, len(encrypted_data), chunk_size):
        chunk = encrypted_data[i:i+chunk_size]
        decrypted_chunk = private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_chunks.append(decrypted_chunk)

    return b''.join(decrypted_chunks)

def encrypt_file_object(file_object, public_key: str) -> str:
    file_content = file_object.read()
    return encrypt_binary_data(file_content, public_key)

def decrypt_file_object(encrypted_content: str, private_key: str) -> BytesIO:
    decrypted_content = decrypt_binary_data(encrypted_content, private_key)
    return BytesIO(decrypted_content)