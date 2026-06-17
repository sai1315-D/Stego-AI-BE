from fastapi import APIRouter, Depends, HTTPException, status
from app.core.security import get_current_user_id
from app.core.database import supabase
from app.models.schemas import SettingsUpdate

router = APIRouter(prefix="/settings", tags=["Settings"])

@router.get("")
async def get_settings(user_id: str = Depends(get_current_user_id)):
    try:
        res = supabase.table("settings").select("*").eq("user_id", user_id).execute()
        if not res.data:
            # If default settings don't exist for some reason, create them
            insert_res = supabase.table("settings").insert({
                "user_id": user_id,
                "notifications_enabled": True,
                "alert_sound_enabled": True,
                "background_scan_enabled": True,
                "auto_scan_enabled": True,
                "dark_mode": False
            }).execute()
            return insert_res.data[0]
            
        return res.data[0]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch settings: {str(e)}"
        )

@router.put("")
async def update_settings(settings_data: SettingsUpdate, user_id: str = Depends(get_current_user_id)):
    try:
        # Filter out None fields to perform partial updates
        update_payload = {k: v for k, v in settings_data.model_dump().items() if v is not None}
        if not update_payload:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No values provided to update.")
            
        res = supabase.table("settings").update(update_payload).eq("user_id", user_id).execute()
        if not res.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Settings record not found.")
            
        return res.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update settings: {str(e)}"
        )
