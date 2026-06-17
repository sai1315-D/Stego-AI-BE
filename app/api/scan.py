from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status
from app.models.schemas import ScanResponse
from app.core.security import get_current_user_id
from app.core.database import supabase
from app.services.ai_engine import ai_engine
import traceback

router = APIRouter(prefix="/scan", tags=["Scanning"])

async def handle_file_scan(file: UploadFile, file_type: str, user_id: str) -> dict:
    try:
        # Read file bytes
        file_bytes = await file.read()
        
        # Analyze file via AI Engine
        result = ai_engine.analyze_file(file_bytes, file.filename, file_type)
        
        # Save scan history record to Supabase
        scan_record = {
            "user_id": user_id,
            "file_name": result["file_name"],
            "file_type": result["file_type"],
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "scan_result": result["metrics"] # store the raw DSP metrics
        }
        
        db_res = supabase.table("scan_history").insert(scan_record).execute()
        if not db_res.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save scan history."
            )
            
        # If threat is detected (SUSPICIOUS or DANGEROUS), save log in threat_logs
        if result["risk_level"] in ["SUSPICIOUS", "DANGEROUS"]:
            threat_log = {
                "user_id": user_id,
                "file_name": result["file_name"],
                "threat_level": result["risk_level"],
                "description": result["description"]
            }
            supabase.table("threat_logs").insert(threat_log).execute()
            
        return result
        
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred during steganography scan: {str(e)}"
        )

@router.post("/image", response_model=ScanResponse)
async def scan_image(
    file: UploadFile = File(...),
    user_id: str = Depends(get_current_user_id)
):
    return await handle_file_scan(file, "image", user_id)

@router.post("/audio", response_model=ScanResponse)
async def scan_audio(
    file: UploadFile = File(...),
    user_id: str = Depends(get_current_user_id)
):
    return await handle_file_scan(file, "audio", user_id)

@router.post("/video", response_model=ScanResponse)
async def scan_video(
    file: UploadFile = File(...),
    user_id: str = Depends(get_current_user_id)
):
    return await handle_file_scan(file, "video", user_id)

@router.post("/document", response_model=ScanResponse)
async def scan_document(
    file: UploadFile = File(...),
    user_id: str = Depends(get_current_user_id)
):
    return await handle_file_scan(file, "document", user_id)
