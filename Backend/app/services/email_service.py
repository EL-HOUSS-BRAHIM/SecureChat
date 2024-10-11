import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
# Function to send a general email
def send_verification_email(to_email: str, body: str):
    smtp_server = os.getenv('smtp_server')
    smtp_port = 587  # Use 25 if you encounter issues with 587
    username = os.getenv('smtp_username')
    password = os.getenv('smtp_password')  # Make sure to set your password here

    subject = "Email Verification"  # You can customize this subject if needed

    msg = MIMEMultipart()
    msg['From'] = username
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
            server.login(username, password)
            server.sendmail(username, to_email, msg.as_string())
        print("Verification email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Function to send an OTP email
def send_otp_email(email: str, otp: str):
    body = f"Your login OTP code is: {otp}"
    send_verification_email(email, body)

# Function to send a 2FA email
def send_2fa_email(email: str, totp_code: str):
    body = f"Your 2FA code is: {totp_code}"
    send_verification_email(email, body)

# Ensure the functions are called correctly in your login logic
