from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="CyberGuard API",
    description="CyberGuard cybersecurity analysis backend",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "status": "online",
        "message": "CyberGuard Backend is running"
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "CyberGuard API"
    }