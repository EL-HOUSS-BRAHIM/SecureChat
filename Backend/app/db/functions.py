from app.models import message, user
from app.core.encryption import decrypt_message, encrypt_message
from sqlalchemy.orm import Session
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def reencrypt_messages(db: Session):
    users = db.query(user.User).all()
    user_keys = {u.id: (u.public_key, u.private_key) for u in users}

    messages = db.query(message.Message).all()
    for msg in messages:
        logger.info(f"Re-encrypting message {msg.id} (sender: {msg.sender_id}, receiver: {msg.receiver_id})")
        try:
            # Decrypt with the sender's private key
            decrypted = decrypt_message(msg.encrypted_content, user_keys[msg.sender_id][1])
            if decrypted == "[Decryption failed]":
                logger.error(f"Failed to decrypt message {msg.id}")
                continue
            logger.info(f"Successfully decrypted message {msg.id}")

            # Re-encrypt with the receiver's public key
            reencrypted = encrypt_message(decrypted, user_keys[msg.receiver_id][0])
            msg.encrypted_content = reencrypted
            db.add(msg)
            logger.info(f"Successfully re-encrypted message {msg.id}")
        except Exception as e:
            logger.error(f"Error processing message {msg.id}: {str(e)}")

    db.commit()
    logger.info("Finished re-encrypting messages")


