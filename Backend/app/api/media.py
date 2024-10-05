from fastapi import APIRouter, UploadFile, File
from app.core.encryption import encrypt_image, decrypt_image

router = APIRouter()

@router.post("/media/upload")
async def upload_media(file: UploadFile = File(...)):
    encrypted_file = encrypt_image(file.file)
    # Logic to store encrypted image
    return {"msg": "File uploaded successfully"}

@router.get("/media/retrieve/{message_id}")
def retrieve_media(message_id: int):
    # Logic to retrieve encrypted image
    encrypted_image = "dummy_encrypted_image"  # Dummy image
    decrypted_image = decrypt_image(encrypted_image)
    return {"image": decrypted_image}
