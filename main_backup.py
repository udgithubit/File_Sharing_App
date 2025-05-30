from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timedelta
from jose import JWTError, jwt
from itsdangerous import URLSafeTimedSerializer
import smtplib
import os
import mimetypes
from typing import List
from passlib.context import CryptContext
from fastapi.responses import Response

# Configuration
SECRET_KEY = "your-secret-key-1234567890"  # Replace with secure key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
MONGO_URI = "mongodb://localhost:27017"
UPLOAD_DIR = "./uploads"

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
serializer = URLSafeTimedSerializer(SECRET_KEY)  # Use SECRET_KEY for all token operations

# MongoDB setup
client = AsyncIOMotorClient(MONGO_URI)
db = client.file_sharing_db
users_collection = db.users
files_collection = db.files

# Ensure upload directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Pydantic Models
class User(BaseModel):
    email: EmailStr
    password: str
    role: str  # "ops" or "client"

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class FileMetadata(BaseModel):
    filename: str
    uploaded_by: str
    upload_date: datetime
    assignment_id: str

# Helper Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_user(email: str):
    user = await users_collection.find_one({"email": email})
    if user:
        return UserInDB(**user)

async def authenticate_user(email: str, password: str):
    user = await get_user(email)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        role: str = payload.get("role")
        if email is None or role is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = await get_user(email)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def send_verification_email(email: str) -> str:
    token = serializer.dumps(email, salt="email-verify")
    verification_url = f"http://localhost:8000/verify-email/{token}"
    # Simulate email sending (replace with actual SMTP server details)
    print(f"Verification email sent to {email} with URL: {verification_url}")
    return verification_url

# API Endpoints
@app.post("/signup", response_model=dict)
async def signup(user: User):
    if user.role not in ["client", "ops"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    existing_user = await get_user(user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    user_dict = user.dict()
    user_dict["hashed_password"] = hashed_password
    user_dict["verified"] = False  # Add verified field
    del user_dict["password"]
    await users_collection.insert_one(user_dict)
    verification_url = send_verification_email(user.email)
    return {"message": "User created, verification email sent", "verification_url": verification_url}

@app.get("/verify-email/{token}")
async def verify_email(token: str):
    try:
        email = serializer.loads(token, salt="email-verify", max_age=86400)  # 24 hours for testing
        user = await get_user(email)
        if not user:
            raise HTTPException(status_code=400, detail="Invalid email")
        # Check if verified field exists, set to True
        result = await users_collection.update_one(
            {"email": email, "verified": {"$in": [False, None]}},  # Handle missing verified field
            {"$set": {"verified": True}}
        )
        if result.modified_count == 0:
            raise HTTPException(status_code=400, detail="Already verified or invalid user")
        return {"message": "Email verified successfully"}
    except:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/upload-file")
async def upload_file(file: UploadFile = File(...), current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "ops":
        raise HTTPException(status_code=403, detail="Only ops users can upload files")

    # Validate file type
    allowed_types = [".pptx", ".docx", ".xlsx"]
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in allowed_types:
        raise HTTPException(status_code=400, detail="Only pptx, docx, xlsx files allowed")

    # Save file
    assignment_id = str(os.urandom(16).hex())
    file_path = os.path.join(UPLOAD_DIR, f"{assignment_id}_{file.filename}")
    with open(file_path, "wb") as f:
        f.write(await file.read())

    # Store metadata
    file_metadata = {
        "filename": file.filename,
        "uploaded_by": current_user.email,
        "upload_date": datetime.utcnow(),
        "assignment_id": assignment_id,
        "file_path": file_path
    }
    await files_collection.insert_one(file_metadata)
    return {"message": "File uploaded successfully", "assignment_id": assignment_id}

@app.get("/list-files", response_model=List[FileMetadata])
async def list_files(current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "client":
        raise HTTPException(status_code=403, detail="Only client users can list files")
    files = []
    async for file in files_collection.find():
        files.append(FileMetadata(**file))
    return files

@app.get("/download-file/{assignment_id}")
async def download_file(assignment_id: str, current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "client":
        raise HTTPException(status_code=403, detail="Only client users can download files")
    file_metadata = await files_collection.find_one({"assignment_id": assignment_id})
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found")

    # Generate secure URL
    token = serializer.dumps({"assignment_id": assignment_id, "email": current_user.email}, salt="download-file")
    download_url = f"http://localhost:8000/serve-file/{token}"
    return {"message": "success", "download-link": download_url}

@app.get("/serve-file/{token}")
async def serve_file(token: str, current_user: UserInDB = Depends(get_current_user)):
    try:
        data = serializer.loads(token, salt="download-file", max_age=3600)
        if data["email"] != current_user.email:
            raise HTTPException(status_code=403, detail="Unauthorized access")
        file_metadata = await files_collection.find_one({"assignment_id": data["assignment_id"]})
        if not file_metadata:
            raise HTTPException(status_code=404, detail="File not found")

        # Serve file
        file_path = file_metadata["file_path"]
        content_type, _ = mimetypes.guess_type(file_path)
        with open(file_path, "rb") as f:
            content = f.read()
        return Response(content=content, media_type=content_type,
                        headers={"Content-Disposition": f"attachment; filename={file_metadata['filename']}"})
    except:
        raise HTTPException(status_code=400, detail="Invalid or expired token")