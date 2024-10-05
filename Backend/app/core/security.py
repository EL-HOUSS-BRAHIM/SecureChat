import pyotp

def generate_totp() -> str:
    # Generate a TOTP secret
    totp = pyotp.TOTP(pyotp.random_base32())
    return totp.provisioning_uri(name="YourApp", issuer_name="YourCompany")

def verify_totp(secret: str, totp_code: str) -> bool:
    # Verify the provided TOTP code
    totp = pyotp.TOTP(secret)
    return totp.verify(totp_code)
