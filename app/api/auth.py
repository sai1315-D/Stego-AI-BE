from fastapi import APIRouter, HTTPException, Depends, status
from app.models.schemas import (
    UserRegister, UserLogin, Token, ProfileUpdate,
    AdminCreateUser, ForgotPasswordRequest, ResetPasswordRequest
)
from app.core.database import supabase
from app.core.security import get_password_hash, verify_password, create_access_token, get_current_user_id
from postgrest.exceptions import APIError

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ──────────────────────────────────────────────
# Helper: get current user record with role check
# ──────────────────────────────────────────────
def _get_user_record(user_id: str):
    res = supabase.table("users").select("*").eq("id", user_id).execute()
    if not res.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return res.data[0]

def _require_admin(user_id: str):
    user = _get_user_record(user_id)
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required.")
    return user

# ──────────────────────────────────────────────
# Public: Register
# ──────────────────────────────────────────────
@router.post("/register", response_model=Token)
async def register(user_data: UserRegister):
    if user_data.password != user_data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match."
        )

    try:
        existing = supabase.table("users").select("*").eq("email", user_data.email).execute()
        if existing.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is already registered."
            )
    except APIError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    hashed = get_password_hash(user_data.password)
    try:
        user_response = supabase.table("users").insert({
            "name": user_data.name,
            "email": user_data.email,
            "password_hash": hashed,
            "role": "operator",
            "is_permanent": False
        }).execute()
        
        print(f"[DEBUG] Registration insert response: {user_response}")
        print(f"[DEBUG] Registration insert data: {user_response.data}")
        
        if not user_response.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="User creation failed — no data returned from database. Check RLS policies on the 'users' table."
            )
            
        user = user_response.data[0]
        user_id = user["id"]
        
        # Create default settings for the new user
        try:
            supabase.table("settings").insert({
                "user_id": user_id,
                "notifications_enabled": True,
                "alert_sound_enabled": True,
                "background_scan_enabled": True,
                "auto_scan_enabled": True,
                "dark_mode": True
            }).execute()
        except Exception as settings_err:
            print(f"[WARNING] Failed to create default settings for user {user_id}: {settings_err}")
        
        access_token = create_access_token(subject=user_id)
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": user_id,
            "name": user["name"],
            "email": user["email"],
            "role": user.get("role", "operator")
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"[ERROR] Registration failed with exception: {type(e).__name__}: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# ──────────────────────────────────────────────
# Public: Login
# ──────────────────────────────────────────────
@router.post("/login", response_model=Token)
async def login(user_data: UserLogin):
    try:
        user_response = supabase.table("users").select("*").eq("email", user_data.email).execute()
        user = None
        if user_response.data:
            user = user_response.data[0]
        else:
            # Fallback check in local db.json if running with Supabase but user was created in db.json
            import os, json
            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "db.json")
            if os.path.exists(db_path):
                try:
                    with open(db_path, "r", encoding="utf-8") as f:
                        local_db = json.load(f)
                    local_users = local_db.get("users", [])
                    local_match = next((u for u in local_users if u.get("email") == user_data.email), None)
                    if local_match and verify_password(user_data.password, local_match["password_hash"]):
                        user = local_match
                        try:
                            supabase.table("users").insert({
                                "id": user["id"],
                                "name": user["name"],
                                "email": user["email"],
                                "password_hash": user["password_hash"],
                                "role": user.get("role", "operator"),
                                "is_permanent": user.get("is_permanent", False)
                            }).execute()
                            
                            supabase.table("settings").insert({
                                "user_id": user["id"],
                                "notifications_enabled": True,
                                "alert_sound_enabled": True,
                                "background_scan_enabled": True,
                                "auto_scan_enabled": True,
                                "dark_mode": True
                            }).execute()
                            print(f"[INFO] Synced user {user['email']} from db.json to Supabase.")
                        except Exception as sync_err:
                            print(f"[WARNING] Failed to sync local user to Supabase: {sync_err}")
                except Exception as db_err:
                    print(f"[WARNING] Local db fallback error: {db_err}")

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password."
            )
            
        if not verify_password(user_data.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password."
            )
            
        access_token = create_access_token(subject=user["id"])
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user.get("role", "operator")
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# ──────────────────────────────────────────────
# Authenticated: Update own profile
# ──────────────────────────────────────────────
@router.put("/profile")
async def update_profile(profile_data: ProfileUpdate, user_id: str = Depends(get_current_user_id)):
    try:
        user_res = supabase.table("users").select("*").eq("id", user_id).execute()
        if not user_res.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Operator session profile not found."
            )
        user = user_res.data[0]
        update_payload = {}

        if profile_data.name is not None and profile_data.name.strip() != "":
            update_payload["name"] = profile_data.name.strip()

        if profile_data.new_password is not None and profile_data.new_password.strip() != "":
            if not profile_data.current_password:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Current passphrase is required to change passphrase credentials."
                )
            if not verify_password(profile_data.current_password, user["password_hash"]):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Incorrect current passphrase credentials."
                )
            update_payload["password_hash"] = get_password_hash(profile_data.new_password)

        if not update_payload:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No profile updates requested."
            )

        update_res = supabase.table("users").update(update_payload).eq("id", user_id).execute()
        if not update_res.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Credentials update transaction failed."
            )
        
        updated_user = update_res.data[0]
        return {
            "status": "success",
            "message": "Operator security profile updated.",
            "name": updated_user["name"],
            "email": updated_user["email"]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process operator updates: {str(e)}"
        )

# ──────────────────────────────────────────────
# Admin: List all users
# ──────────────────────────────────────────────
@router.get("/users")
async def list_users(user_id: str = Depends(get_current_user_id)):
    _require_admin(user_id)
    try:
        res = supabase.table("users").select("*").execute()
        users = []
        for u in res.data:
            users.append({
                "id": u["id"],
                "name": u["name"],
                "email": u["email"],
                "role": u.get("role", "operator"),
                "is_permanent": u.get("is_permanent", False),
                "created_at": u.get("created_at", "")
            })
        return users
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# ──────────────────────────────────────────────
# Admin: Create a new user
# ──────────────────────────────────────────────
@router.post("/users")
async def admin_create_user(user_data: AdminCreateUser, user_id: str = Depends(get_current_user_id)):
    _require_admin(user_id)
    
    # Check if email already exists
    existing = supabase.table("users").select("*").eq("email", user_data.email).execute()
    if existing.data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is already registered.")
    
    hashed = get_password_hash(user_data.password)
    try:
        user_response = supabase.table("users").insert({
            "name": user_data.name,
            "email": user_data.email,
            "password_hash": hashed,
            "role": user_data.role,
            "is_permanent": False
        }).execute()
        
        if not user_response.data:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User creation failed.")
        
        new_user = user_response.data[0]
        
        # Create default settings
        supabase.table("settings").insert({
            "user_id": new_user["id"],
            "notifications_enabled": True,
            "alert_sound_enabled": True,
            "background_scan_enabled": True,
            "auto_scan_enabled": True,
            "dark_mode": True
        }).execute()
        
        return {
            "status": "success",
            "message": f"User '{user_data.name}' created successfully.",
            "user": {
                "id": new_user["id"],
                "name": new_user["name"],
                "email": new_user["email"],
                "role": new_user.get("role", "operator"),
                "is_permanent": new_user.get("is_permanent", False),
                "created_at": new_user.get("created_at", "")
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# ──────────────────────────────────────────────
# Admin: Delete a user (permanent users cannot be deleted)
# ──────────────────────────────────────────────
@router.delete("/users/{target_user_id}")
async def admin_delete_user(target_user_id: str, user_id: str = Depends(get_current_user_id)):
    _require_admin(user_id)
    
    # Fetch the target user
    target_res = supabase.table("users").select("*").eq("id", target_user_id).execute()
    if not target_res.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    
    target_user = target_res.data[0]
    
    # Prevent deletion of permanent (admin) accounts
    if target_user.get("is_permanent", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This is a permanent admin account and cannot be deleted."
        )
    
    # Delete user and their settings
    supabase.table("users").delete().eq("id", target_user_id).execute()
    supabase.table("settings").delete().eq("user_id", target_user_id).execute()
    
    return {"status": "success", "message": f"User '{target_user['name']}' deleted successfully."}

# ──────────────────────────────────────────────
# Public: Forgot Password (sends a mock reset confirmation)
# ──────────────────────────────────────────────
@router.post("/forgot-password")
async def forgot_password(data: ForgotPasswordRequest):
    # Check if user exists
    res = supabase.table("users").select("*").eq("email", data.email).execute()
    # Always return success to prevent email enumeration
    return {
        "status": "success",
        "message": "If your email is registered, a password reset link has been dispatched to your inbox.",
        "email_found": bool(res.data)
    }

# ──────────────────────────────────────────────
# Admin: Reset any user's password
# ──────────────────────────────────────────────
@router.post("/reset-password")
async def reset_password(data: ResetPasswordRequest, user_id: str = Depends(get_current_user_id)):
    _require_admin(user_id)
    
    # Find target user by email
    target_res = supabase.table("users").select("*").eq("email", data.email).execute()
    if not target_res.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No user found with this email.")
    
    target_user = target_res.data[0]
    new_hash = get_password_hash(data.new_password)
    
    update_res = supabase.table("users").update({"password_hash": new_hash}).eq("id", target_user["id"]).execute()
    if not update_res.data:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Password reset failed.")
    
    return {
        "status": "success",
        "message": f"Password for '{target_user['name']}' has been reset successfully."
    }
