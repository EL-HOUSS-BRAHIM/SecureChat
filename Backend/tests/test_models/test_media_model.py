# tests/test_models/test_media.py
import pytest
from app.models.media import Media  # Make sure this import matches your actual model

def test_media_creation():
    media = Media(
        user_id=1,
        encrypted_content=b"encrypted_image_data",
        media_type="image/jpeg"
    )
    assert media.user_id == 1
    assert media.encrypted_content == b"encrypted_image_data"
    assert media.media_type == "image/jpeg"