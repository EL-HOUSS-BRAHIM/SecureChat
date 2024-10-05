from fastapi import BackgroundTasks
from email.mime.text import MIMEText
import smtplib

# Email configuration settings (update with actual email provider and credentials)
SMTP_SERVER = "smtp.mailtrap.io"
SMTP_PORT = 587
SMTP_USERNAME = "your_username"
SMTP_PASSWORD = "your_password"

def send_verification_email(email: str, token: str):
    subject = "Verify Your Email"
    body = f"Please verify your email by clicking the link: https://yourapp.com/verify?token={token}"
    send_email(email, subject, body)

def send_2fa_email(email: str, totp_code: str):
    subject = "Your 2FA Code"
    body = f"Your 2FA code is: {totp_code}"
    send_email(email, subject, body)

def send_email(email: str, subject: str, body: str):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USERNAME
    msg['To'] = email

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, email, msg.as_string())
