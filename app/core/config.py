import os
from pathlib import Path
from pydantic_settings import BaseSettings

# Compute absolute path to backend/.env so it works regardless of cwd
_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI Cyber Shield Steganography Detection Engine"
    
    # Supabase configurations
    SUPABASE_URL: str = "https://placeholder-project.supabase.co"
    SUPABASE_KEY: str = "placeholder-key"
    
    # JWT Auth configurations
    JWT_SECRET: str = "super-secret-key-change-it-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours default
    VIRUSTOTAL_API_KEY: str = "6310a37664cc7685d55e3401d2149027ebd4d305f51ccae740c3c2ec18709da8"

    class Config:
        case_sensitive = True
        env_file = str(_ENV_FILE)

settings = Settings()
