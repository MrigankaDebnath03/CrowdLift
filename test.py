from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from typing import List, Optional
import logging
from pymongo.errors import PyMongoError

app = FastAPI()

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017")
db = client["crowdfunding_db"]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = "dAytE3tEgU9niRMeblMrzDshGGGJEMup"  # Change this to a secure secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type, _handler):
        from pydantic_core import core_schema
        return core_schema.json_or_python_schema(
            json_schema=core_schema.str_schema(),
            python_schema=core_schema.is_instance_schema(ObjectId),
            serialization=core_schema.plain_serializer_function_ser_schema(str),
        )

class User(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    username: str
    email: str

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str}
    }

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class ProjectCreate(BaseModel):
    title: str
    description: str
    fundraising_goal: float
    start_date: str
    raising_funds: bool = True
    funds_raised: float = 0
    progress: float = 0
    youtube_url: Optional[str] = None

class Project(ProjectCreate):
    id: str
    owner_id: str

# class Donation(BaseModel):
#     project_id: str
#     amount: float

class Donation(BaseModel):
    project_id: str
    amount: float
    message: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    user = db.users.find_one({"username": username})
    if not user or not verify_password(password, user["password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.users.find_one({"username": username})
    if user is None:
        raise credentials_exception
    return User(**user)

@app.post("/register", response_model=User)
async def register(user: UserCreate):
    if db.users.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    user_dict = user.dict()
    user_dict["password"] = hashed_password
    result = db.users.insert_one(user_dict)
    user_dict["id"] = str(result.inserted_id)
    return User(**user_dict)

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/projects", response_model=Project)
async def create_project(project: ProjectCreate, current_user: User = Depends(get_current_user)):
    try:
        db.command('ping')
        logger.debug("MongoDB connection is active")
        
        logger.debug(f"Attempting to create project: {project}")
        logger.debug(f"Current user: {current_user}")
        
        project_dict = project.dict()
        project_dict["owner_id"] = str(current_user.id)
        
        logger.debug(f"Project dict: {project_dict}")
        
        result = db.projects.insert_one(project_dict)
        
        logger.debug(f"Insert result: {result}")
        
        project_dict["id"] = str(result.inserted_id)
        return Project(**project_dict)
    except PyMongoError as e:
        logger.error(f"MongoDB error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Validation error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/projects", response_model=List[Project])
async def get_projects():
    projects = list(db.projects.find({"raising_funds": True}))
    for project in projects:
        project["id"] = str(project["_id"])
    return projects

@app.post("/donate", response_model=Project)
async def donate(donation: Donation, current_user: User = Depends(get_current_user)):
    try:
        project = db.projects.find_one({"_id": ObjectId(donation.project_id)})
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        if not project["raising_funds"]:
            raise HTTPException(status_code=400, detail="This project is not currently accepting donations")
        
        new_funds_raised = project["funds_raised"] + donation.amount
        
        db.projects.update_one(
            {"_id": ObjectId(donation.project_id)},
            {
                "$set": {
                    "funds_raised": new_funds_raised
                },
                "$push": {
                    "donations": {
                        "user_id": str(current_user.id),
                        "amount": donation.amount,
                        "message": donation.message,
                        "date": datetime.utcnow()
                    }
                }
            }
        )
        
        db.donations.insert_one({
            "user_id": str(current_user.id),
            "project_id": donation.project_id,
            "amount": donation.amount,
            "message": donation.message,
            "date": datetime.utcnow()
        })
        
        updated_project = db.projects.find_one({"_id": ObjectId(donation.project_id)})
        updated_project["id"] = str(updated_project["_id"])
        return Project(**updated_project)
    except PyMongoError as e:
        logger.error(f"MongoDB error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Validation error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")



@app.get("/user/investments", response_model=List[dict])
async def get_user_investments(current_user: User = Depends(get_current_user)):
    donations = list(db.donations.find({"user_id": current_user.id}))
    investments = []
    for donation in donations:
        project = db.projects.find_one({"_id": ObjectId(donation["project_id"])})
        if project:
            investments.append({
                "project_id": str(project["_id"]),
                "title": project["title"],
                "amount_invested": donation["amount"],
                "date": donation["date"]
            })
    return investments


@app.put("/projects/{project_id}", response_model=Project)
async def update_project(project_id: str, project_update: ProjectCreate, current_user: User = Depends(get_current_user)):
    try:
        existing_project = db.projects.find_one({"_id": ObjectId(project_id), "owner_id": str(current_user.id)})
        if not existing_project:
            raise HTTPException(status_code=404, detail="Project not found or you don't have permission to update it")
        
        update_data = project_update.dict(exclude_unset=True)
        db.projects.update_one({"_id": ObjectId(project_id)}, {"$set": update_data})
        
        updated_project = db.projects.find_one({"_id": ObjectId(project_id)})
        updated_project["id"] = str(updated_project["_id"])
        return Project(**updated_project)
    except PyMongoError as e:
        logger.error(f"MongoDB error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Validation error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/user/projects", response_model=List[Project])
async def get_user_projects(current_user: User = Depends(get_current_user)):
    try:
        user_projects = list(db.projects.find({"owner_id": str(current_user.id)}))
        for project in user_projects:
            project["id"] = str(project["_id"])
        return [Project(**project) for project in user_projects]
    except PyMongoError as e:
        logger.error(f"MongoDB error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
