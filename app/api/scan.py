from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status
from app.models.schemas import ScanResponse
from app.core.security import get_current_user_id
from app.core.database import supabase
from app.services.ai_engine import ai_engine
import traceback
import time
import hashlib

router = APIRouter(prefix="/scan", tags=["Scanning"])

async def handle_file_scan(file: UploadFile, file_type: str, user_id: str) -> dict:
    try:
        scan_start = time.time()
        
        # Read file bytes
        file_bytes = await file.read()
        
        # Enforce 50MB file size limit
        MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
        if len(file_bytes) > MAX_FILE_SIZE:
            size_mb = round(len(file_bytes) / (1024 * 1024), 2)
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File \"{file.filename}\" is {size_mb} MB — exceeds the 50 MB upload limit."
            )
        
        # Compute file hash
        file_sha256 = hashlib.sha256(file_bytes).hexdigest()
        
        # Analyze file via AI Engine
        result = ai_engine.analyze_file(file_bytes, file.filename, file_type)
        
        # Run ExifTool analysis
        from app.services.exiftool_service import exiftool_service
        exif_res = exiftool_service.analyze_metadata(file_bytes, file.filename)
        result["exiftool_results"] = exif_res
        
        # Adjust risk based on ExifTool indicators
        if exif_res.get("stego_indicators"):
            impact = exif_res["risk_score_impact"]
            result["risk_score"] = min(100, result["risk_score"] + impact)
            result["threat_probability"] = result["risk_score"] / 100.0
            
            # Recalculate level
            if result["risk_score"] > 70:
                result["risk_level"] = "DANGEROUS"
            elif result["risk_score"] > 30 and result["risk_level"] == "SAFE":
                result["risk_level"] = "SUSPICIOUS"
                
            # Add description details
            bullet_points = "; ".join([ind["description"] for ind in exif_res["stego_indicators"]])
            result["description"] = f"ExifTool Metadata Anomalies Detected: {bullet_points}. " + result["description"]
            
        # Query VirusTotal API
        from app.services.virustotal import scan_file_bytes
        vt_res = scan_file_bytes(file_bytes, file.filename)
        
        # Integrate VirusTotal threat details
        result["vt_results"] = vt_res
        
        if vt_res and vt_res.get("status") == "success" and vt_res.get("data"):
            vt_data = vt_res["data"]
            vt_stats = vt_data.get("stats", {})
            malicious_count = vt_stats.get("malicious", 0)
            suspicious_count = vt_stats.get("suspicious", 0)
            
            if malicious_count > 0:
                result["risk_level"] = "DANGEROUS"
                result["risk_score"] = max(result["risk_score"], min(100, 75 + malicious_count * 5))
                result["threat_probability"] = result["risk_score"] / 100.0
                result["description"] = f"Threat Alert: Flagged as MALICIOUS by {malicious_count} VirusTotal engines. " + result["description"]
            elif suspicious_count > 0:
                result["risk_level"] = "SUSPICIOUS"
                result["risk_score"] = max(result["risk_score"], min(70, 45 + suspicious_count * 10))
                result["threat_probability"] = result["risk_score"] / 100.0
                result["description"] = f"Security Warning: Flagged as SUSPICIOUS by {suspicious_count} VirusTotal engines. " + result["description"]
        
        # Compute scan duration
        scan_duration_ms = round((time.time() - scan_start) * 1000)
        result["scan_duration_ms"] = scan_duration_ms
        result["file_size"] = len(file_bytes)
        result["sha256"] = file_sha256
        
        # Save scan history record to database
        scan_record = {
            "user_id": user_id,
            "file_name": result["file_name"],
            "file_type": result["file_type"],
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "scan_result": {
                **result["metrics"],
                "vt_results": vt_res,
                "exiftool_results": exif_res
            }
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
