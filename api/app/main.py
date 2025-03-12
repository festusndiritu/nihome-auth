from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
import bcrypt
import random
import string
from datetime import datetime, timedelta
from jose import jwt
from dotenv import load_dotenv
import os
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
import base64
from email.mime.text import MIMEText
from google.auth.transport.requests import Request
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables
load_dotenv()

# Constants
SECRET_KEY = os.getenv("SECRET_KEY")
MONGO_URI = os.getenv("MONGO_URI")
ALGORITHM = "HS256"
OTP_EXPIRY_MINUTES = 10

# Constants for Gmail API
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
CLIENT_ID = os.getenv('GMAIL_CLIENT_ID')
PROJECT_ID = os.getenv('GMAIL_PROJECT_ID')
CLIENT_SECRET = os.getenv('GMAIL_CLIENT_SECRET')
TOKEN_FILE = 'token.json'

# MongoDB Connection
client = MongoClient(MONGO_URI)
db = client["niHome"]
users = db["user_data"]

# FastAPI App
app = FastAPI()

# Utility Functions
def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def send_otp(email: str, otp: str):
    #Placeholder for sending OTP
    print(f"Sending OTP {otp} to {email}")

# Models
class RegisterModel(BaseModel):
    username: str
    email: EmailStr
    password: str
    profile_url: str = None

class LoginModel(BaseModel):
    email: EmailStr
    password: str

class OTPModel(BaseModel):
    email: EmailStr
    otp: str

class ResetPasswordModel(BaseModel):
    email: EmailStr
    new_password: str

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper Functions
def save_otp(email: str, otp: str):
    expiry = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    users.update_one(
        {"email": email},
        {"$set": {"otp": otp, "otp_expiry": expiry}}
    )

def validate_otp(email: str, otp: str):
    user = users.find_one({"email": email})
    if not user or "otp" not in user or user["otp"] != otp:
        return False
    if datetime.utcnow() > user["otp_expiry"]:
        return False
    users.update_one({"email": email}, {"$unset": {"otp": "", "otp_expiry": ""}})
    return True

# Endpoints
@app.post("/auth/register")
def register(user: RegisterModel):
    if users.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already exists.")
    hashed_password = hash_password(user.password)
    otp = generate_otp()
    send_otp(user.email, otp, "register")
    users.insert_one({
        "username": user.username,
        "email": user.email,
        "password": hashed_password,
        "profile_url": user.profile_url,
        "otp": otp,
        "otp_expiry": datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    })
    return {"message": "User registered successfully. OTP sent to email."}

@app.post("/auth/login")
def login(data: LoginModel):
    user = users.find_one({"email": data.email})
    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    otp = generate_otp()
    send_otp(user["email"], otp, "login")
    save_otp(user["email"], otp)
    return {"message": "OTP sent to your email."}

@app.post("/auth/verify_otp")
def verify_otp(data: OTPModel):
    if not validate_otp(data.email, data.otp):
        raise HTTPException(status_code=401, detail="Invalid or expired OTP.")
    token = jwt.encode({"email": data.email, "exp": datetime.utcnow() + timedelta(days=1)}, SECRET_KEY, algorithm=ALGORITHM)
    return {"message": "OTP verified successfully.", "token": token}

@app.post("/auth/forgot_password")
def forgot_password(email: EmailStr):
    user = users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="Email not found.")
    otp = generate_otp()
    send_otp(email, otp, "reset_password")
    save_otp(email, otp)
    return {"message": "OTP sent to your email."}

@app.post("/auth/reset_password")
def reset_password(data: ResetPasswordModel):
    user = users.find_one({"email": data.email})
    if not user:
        raise HTTPException(status_code=404, detail="Email not found.")
    hashed_password = hash_password(data.new_password)
    users.update_one({"email": data.email}, {"$set": {"password": hashed_password}})
    return {"message": "Password reset successfully."}

def authenticate_gmail():
    """Authenticate the Gmail API and return a service instance."""
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_config(
                {
                    "installed": {
                        "client_id": CLIENT_ID,
                        "project_id": PROJECT_ID,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                        "client_secret": CLIENT_SECRET,
                        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
                    }
                },
                SCOPES
            )
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    service = build('gmail', 'v1', credentials=creds)
    return service

def send_otp(email: str, otp: str, purpose: str):
    """Send an OTP using Gmail API with a beautiful HTML message based on the purpose."""
    # Email HTML templates
    messages = {
        'register': f"""
        <html>
        <body>
            <h1>Welcome to niHome</h1>
            <p>Hello,</p>
            <p>Thank you for joining us! Use the OTP below to verify your email:</p>
            <div style="background-color:#f3f4f8;border-radius:4px;color:#050038;font-size:32px;font-style:bold;font-weight:700;height:64px;letter-spacing:normal;line-height:64px;text-align:center; padding-top:12px">{otp}</div>
            <p>If you didn't initiate this request, safely ignore this email.</p>
            <br>
            <p>Best regards,<br>niHome Team</p>
        </body>
        </html>
        """,
        'reset_password': f"""
        <html>
        <body>
            <h1>Password Reset Request</h1>
            <p>Hello,</p>
            <p>We received a request to reset your password. Use the OTP below to proceed:</p>
            <div style="background-color:#f3f4f8;border-radius:4px;color:#050038;font-size:32px;font-style:bold;font-weight:700;height:64px;letter-spacing:normal;line-height:64px;text-align:center; padding-top:12px">{otp}</div>
            <p>If you didn't initiate this request, you can safely ignore this email. No changes have been made to your account</p>
            <br>
            <p>Best regards,<br>niHome Team</p>
        </body>
        </html>
        """,
        'login': f"""
        <html>
        <body>
            <h1>Login Verification</h1>
            <p>Hello,</p>
            <p>We noticed a login attempt to your niHome account. Use the OTP below to verify it's you:</p>
            <div style="background-color:#f3f4f8;border-radius:4px;color:#050038;font-size:32px;font-style:bold;font-weight:700;height:64px;letter-spacing:normal;line-height:64px;text-align:center; padding-top:12px">{otp}</div>
            <p>If you didn't initiate this request, safely ignore this email.</p>
            <br>
            <p>Best regards,<br>niHome Team</p>
        </body>
        </html>
        """,
    }

    html_message = messages.get(purpose, f"""
    <html>
    <body>
        <p>Your OTP is: <strong>{otp}</strong></p>
    </body>
    </html>
    """)

    # Create MIME message
    message = MIMEMultipart("alternative")
    message['to'] = email
    message['from'] = formataddr(("niHome Team", "schattyteam@gmail.com"))
    message['subject'] = "Your OTP Code"

    message.attach(MIMEText(html_message, "html"))

    # Encode the message
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    # Authenticate and send the email
    try:
        service = authenticate_gmail()
        service.users().messages().send(
            userId="me",
            body={"raw": raw_message}
        ).execute()
    except Exception as e:
        print(f"An error occurred: {e}")