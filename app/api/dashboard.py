from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import StreamingResponse
from app.core.security import get_current_user_id
from app.core.database import supabase
from app.models.schemas import DashboardStats
from typing import List, Optional
import csv
import io
from datetime import datetime

router = APIRouter(tags=["Dashboard & Reports"])

@router.get("/dashboard", response_model=DashboardStats)
async def get_dashboard(user_id: str = Depends(get_current_user_id)):
    try:
        # Fetch all scan history entries for the user
        history_res = supabase.table("scan_history").select("*").eq("user_id", user_id).order("created_at", desc=True).execute()
        scans = history_res.data or []
        
        # Calculate stats card data
        total_files = len(scans)
        safe_files = sum(1 for s in scans if s["risk_level"] == "SAFE")
        suspicious_files = sum(1 for s in scans if s["risk_level"] == "SUSPICIOUS")
        dangerous_files = sum(1 for s in scans if s["risk_level"] == "DANGEROUS")
        total_threats = suspicious_files + dangerous_files
        
        # Fetch threat logs for the recent alerts section
        alerts_res = supabase.table("threat_logs").select("*").eq("user_id", user_id).order("created_at", desc=True).limit(5).execute()
        recent_alerts = alerts_res.data or []
        
        return {
            "total_files_scanned": total_files,
            "total_threats_detected": total_threats,
            "safe_files": safe_files,
            "suspicious_files": suspicious_files,
            "dangerous_files": dangerous_files,
            "recent_alerts": recent_alerts,
            "scan_history": scans[:10], # recent 10 scans
            "system_status": "ACTIVE - Background monitoring service is scanning folders."
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compile dashboard metrics: {str(e)}"
        )

@router.get("/scan-history")
async def get_scan_history(
    user_id: str = Depends(get_current_user_id),
    query: Optional[str] = Query(None, description="Search by file name"),
    file_type: Optional[str] = Query(None, description="Filter by file type"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level")
):
    try:
        builder = supabase.table("scan_history").select("*").eq("user_id", user_id)
        
        if file_type:
            builder = builder.eq("file_type", file_type.lower())
        if risk_level:
            builder = builder.eq("risk_level", risk_level.upper())
            
        history_res = builder.order("created_at", desc=True).execute()
        scans = history_res.data or []
        
        # In-memory keyword search filtering (or we could use ILIKE in Postgres)
        if query:
            q_lower = query.lower()
            scans = [s for s in scans if q_lower in s["file_name"].lower()]
            
        return scans
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query scan history: {str(e)}"
        )

@router.delete("/scan-history/{scan_id}")
async def delete_scan_record(scan_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        # Delete scan from history (RLS or backend checks ownership)
        res = supabase.table("scan_history").delete().eq("id", scan_id).eq("user_id", user_id).execute()
        if not res.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan record not found or unauthorized deletion."
            )
        return {"status": "success", "message": "Record successfully deleted."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/threat-reports/{scan_id}")
async def get_threat_report(scan_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        res = supabase.table("scan_history").select("*").eq("id", scan_id).eq("user_id", user_id).execute()
        if not res.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Threat report not found."
            )
            
        scan = res.data[0]
        
        # Recommendations based on risk levels
        recommendations = "No action required."
        if scan["risk_level"] == "SUSPICIOUS":
            recommendations = "Perform manual verification. Do not open custom macros, attachments, or transfer the file to secure environments."
        elif scan["risk_level"] == "DANGEROUS":
            recommendations = "Immediately quarantine or delete this file. It contains high-probability steganographic payload structures."
            
        return {
            "id": scan["id"],
            "file_name": scan["file_name"],
            "file_type": scan["file_type"],
            "risk_score": scan["risk_score"],
            "risk_level": scan["risk_level"],
            "scan_date": scan["created_at"],
            "metrics": scan["scan_result"],
            "recommendations": recommendations,
            "ai_explanation": (
                f"The AI Engine flagged the file as {scan['risk_level']} with a threat probability score of {scan['risk_score']}%. "
                f"This categorization is based on anomalous LSB noise distributions, unexpected Shannon entropy density, "
                f"or hidden metadata signatures."
            )
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/threat-reports/{scan_id}/export-csv")
async def export_report_csv(scan_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        res = supabase.table("scan_history").select("*").eq("id", scan_id).eq("user_id", user_id).execute()
        if not res.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
        scan = res.data[0]
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write report data
        writer.writerow(["Steganography Detection System - Threat Report"])
        writer.writerow([])
        writer.writerow(["Field", "Value"])
        writer.writerow(["Report ID", scan["id"]])
        writer.writerow(["File Name", scan["file_name"]])
        writer.writerow(["File Type", scan["file_type"]])
        writer.writerow(["Risk Score", f"{scan['risk_score']}%"])
        writer.writerow(["Risk Level", scan["risk_level"]])
        writer.writerow(["Scan Date", scan["created_at"]])
        writer.writerow([])
        writer.writerow(["Extraction Metrics Detail"])
        for k, v in scan["scan_result"].items():
            writer.writerow([k, v])
            
        output.seek(0)
        
        headers = {
            'Content-Disposition': f'attachment; filename="stego_report_{scan_id}.csv"'
        }
        return StreamingResponse(io.BytesIO(output.getvalue().encode("utf-8")), media_type="text/csv", headers=headers)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
