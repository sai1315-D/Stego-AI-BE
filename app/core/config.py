import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI Cyber Shield Steganography Detection Engine"
    
    # Supabase configurations
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "https://placeholder-project.supabase.co")
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "placeholder-key")
    
    # JWT Auth configurations
    JWT_SECRET: str = os.getenv("JWT_SECRET", "super-secret-key-change-it-in-production")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440")) # 24 hours default

    class Config:
        case_sensitive = True

settings = Settings()
