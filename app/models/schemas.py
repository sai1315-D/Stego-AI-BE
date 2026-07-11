from pydantic import BaseModel, EmailStr, Field
from typing import Dict, Any, List, Optional
from datetime import datetime

# Auth Schemas
class UserRegister(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=6)
    confirm_password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: str
    name: str
    email: str
    role: Optional[str] = "operator"

# Admin: Create a new user
class AdminCreateUser(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=6)
    role: str = Field(default="operator", pattern="^(admin|operator)$")

# Forgot Password: request reset
class ForgotPasswordRequest(BaseModel):
    email: EmailStr

# Forgot Password: perform reset (admin or self-service with token)
class ResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str = Field(..., min_length=6)

# Scan Response Schema
class ScanResponse(BaseModel):
    file_name: str
    file_type: str
    threat_probability: float
    risk_score: int
    risk_level: str
    description: str
    metrics: Dict[str, Any]
    vt_results: Optional[Dict[str, Any]] = None
    scan_duration_ms: Optional[int] = None
    file_size: Optional[int] = None
    sha256: Optional[str] = None
    exiftool_results: Optional[Dict[str, Any]] = None

# Dashboard Schemas
class DashboardStats(BaseModel):
    total_files_scanned: int
    total_threats_detected: int
    safe_files: int
    suspicious_files: int
    dangerous_files: int
    recent_alerts: List[Dict[str, Any]]
    scan_history: List[Dict[str, Any]]
    system_status: str

# Scan History Schemas
class ScanHistoryItem(BaseModel):
    id: str
    file_name: str
    file_type: str
    risk_score: int
    risk_level: str
    scan_result: Dict[str, Any]
    created_at: datetime

# Settings Schemas
class SettingsUpdate(BaseModel):
    notifications_enabled: Optional[bool] = None
    alert_sound_enabled: Optional[bool] = None
    background_scan_enabled: Optional[bool] = None
    auto_scan_enabled: Optional[bool] = None
    dark_mode: Optional[bool] = None

# Profile Schemas
class ProfileUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    current_password: Optional[str] = None
    new_password: Optional[str] = Field(None, min_length=6)

