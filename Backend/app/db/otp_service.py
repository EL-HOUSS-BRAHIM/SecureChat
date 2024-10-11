from sqlalchemy.orm import Session
from app.models.otp import OTPToken  # Adjust the import based on your structure

class OTPService:

    @staticmethod
    def store_otp(db: Session, email: str, otp: str):
        otp_token = OTPToken(email=email, otp=otp)
        db.add(otp_token)
        db.commit()

    @staticmethod
    def get_otp(db: Session, email: str):
        return db.query(OTPToken).filter(OTPToken.email == email).first()

    @staticmethod
    def clear_otp(db: Session, email: str):
        otp_token = db.query(OTPToken).filter(OTPToken.email == email).first()
        if otp_token:
            db.delete(otp_token)
            db.commit()
