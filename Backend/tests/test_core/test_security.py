# tests/test_core/test_security.py
import pytest
from app.core.security import generate_totp, verify_totp

def test_generate_verify_totp():
    totp_secret = generate_totp()
    totp_code = generate_totp(totp_secret)
    
    assert verify_totp(totp_secret, totp_code)
    assert not verify_totp(totp_secret, "000000")  # Invalid code
