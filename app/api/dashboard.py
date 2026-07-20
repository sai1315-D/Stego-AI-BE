from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import StreamingResponse
from app.core.security import get_current_user_id
from app.core.database import supabase
from app.models.schemas import DashboardStats
from typing import List, Optional
import csv
import io
from datetime import datetime, timedelta

router = APIRouter(tags=["Dashboard & Reports"])

@router.get("/dashboard", response_model=DashboardStats)
async def get_dashboard(user_id: str = Depends(get_current_user_id)):
    try:
        # Delete scan history older than 30 days
        cutoff_date = (datetime.utcnow() - timedelta(days=30)).isoformat()
        try:
            supabase.table("scan_history").delete().eq("user_id", user_id).lt("created_at", cutoff_date).execute()
        except Exception as cleanup_err:
            print(f"Warning: Failed to cleanup old scan history: {cleanup_err}")

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
        # Delete scan history older than 30 days
        cutoff_date = (datetime.utcnow() - timedelta(days=30)).isoformat()
        try:
            supabase.table("scan_history").delete().eq("user_id", user_id).lt("created_at", cutoff_date).execute()
        except Exception as cleanup_err:
            print(f"Warning: Failed to cleanup old scan history: {cleanup_err}")

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
        writer.writerow(["AI CYBER SHIELD - STEGANOGRAPHY THREAT REPORT"])
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
        scan_res = scan.get("scan_result", {})
        for k, v in scan_res.items():
            if k not in ["vt_results", "exiftool_results"]:
                writer.writerow([k, v])

        # ExifTool Stego Indicators
        exif = scan_res.get("exiftool_results", {})
        indicators = exif.get("stego_indicators", [])
        if indicators:
            writer.writerow([])
            writer.writerow(["ExifTool Stego Indicators"])
            writer.writerow(["Type", "Severity", "Description"])
            for ind in indicators:
                writer.writerow([ind.get("type"), ind.get("severity"), ind.get("description")])

        # ExifTool Raw Metadata Tags
        metadata_dict = exif.get("metadata", {})
        if metadata_dict:
            writer.writerow([])
            writer.writerow(["ExifTool Raw Metadata Tags"])
            writer.writerow(["Tag / Field", "Value"])
            for tag, val in metadata_dict.items():
                writer.writerow([tag, val])

        output.seek(0)
        headers = {
            'Content-Disposition': f'attachment; filename="stego_report_{scan_id}.csv"'
        }
        return StreamingResponse(io.BytesIO(output.getvalue().encode("utf-8")), media_type="text/csv", headers=headers)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/threat-reports/{scan_id}/export-json")
async def export_report_json(scan_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        res = supabase.table("scan_history").select("*").eq("id", scan_id).eq("user_id", user_id).execute()
        if not res.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
        scan = res.data[0]
        
        recommendations = "No action required."
        if scan["risk_level"] == "SUSPICIOUS":
            recommendations = "Perform manual verification. Do not open custom macros, attachments, or transfer the file to secure environments."
        elif scan["risk_level"] == "DANGEROUS":
            recommendations = "Immediately quarantine or delete this file. It contains high-probability steganographic payload structures."
            
        report_data = {
            "title": "AI Cyber Shield Threat Analysis Report",
            "report_id": scan["id"],
            "file_name": scan["file_name"],
            "file_type": scan["file_type"],
            "risk_score": scan["risk_score"],
            "risk_level": scan["risk_level"],
            "scan_date": scan["created_at"],
            "recommendations": recommendations,
            "ai_explanation": (
                f"The AI Engine flagged the file as {scan['risk_level']} with a threat probability score of {scan['risk_score']}%. "
                f"This categorization is based on anomalous LSB noise distributions, unexpected Shannon entropy density, "
                f"or hidden metadata signatures."
            ),
            "telemetry_metrics": scan.get("scan_result", {})
        }
        
        import json
        json_bytes = json.dumps(report_data, indent=2).encode("utf-8")
        headers = {
            'Content-Disposition': f'attachment; filename="stego_report_{scan_id}.json"'
        }
        return StreamingResponse(io.BytesIO(json_bytes), media_type="application/json", headers=headers)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/threat-reports/{scan_id}/export-pdf")
async def export_report_pdf(scan_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        res = supabase.table("scan_history").select("*").eq("id", scan_id).eq("user_id", user_id).execute()
        if not res.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
        scan = res.data[0]
        
        recommendations = "No action required."
        if scan["risk_level"] == "SUSPICIOUS":
            recommendations = "Perform manual verification. Do not open custom macros, attachments, or transfer the file to secure environments."
        elif scan["risk_level"] == "DANGEROUS":
            recommendations = "Immediately quarantine or delete this file. It contains high-probability steganographic payload structures."
            
        ai_explanation = (
            f"The AI Engine flagged the file as {scan['risk_level']} with a threat probability score of {scan['risk_score']}%. "
            f"This categorization is based on anomalous LSB noise distributions, unexpected Shannon entropy density, "
            f"or hidden metadata signatures."
        )

        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'DocTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=18, textColor=colors.HexColor('#0f172a'), spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            'DocSubTitle', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#0284c7'), spaceAfter=8
        )
        heading2_style = ParagraphStyle(
            'Heading2Custom', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=12, textColor=colors.HexColor('#0f172a'), spaceBefore=10, spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyCustom', parent=styles['Normal'], fontName='Helvetica', fontSize=9, leading=13, textColor=colors.HexColor('#334155')
        )
        small_style = ParagraphStyle(
            'SmallCustom', parent=styles['Normal'], fontName='Helvetica', fontSize=8, leading=11, textColor=colors.HexColor('#334155')
        )

        elements = []
        elements.append(Paragraph("AI CYBER SHIELD", subtitle_style))
        elements.append(Paragraph("Steganography Threat Analysis Report", title_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=12))

        risk_hex = '#16a34a' if scan['risk_level'] == 'SAFE' else ('#d97706' if scan['risk_level'] == 'SUSPICIOUS' else '#dc2626')

        meta_data = [
            [Paragraph("<b>Report ID:</b>", body_style), Paragraph(str(scan['id']), body_style)],
            [Paragraph("<b>File Name:</b>", body_style), Paragraph(str(scan['file_name']), body_style)],
            [Paragraph("<b>Format Category:</b>", body_style), Paragraph(str(scan['file_type']).upper(), body_style)],
            [Paragraph("<b>Probability Score:</b>", body_style), Paragraph(f"<font color='{risk_hex}'><b>{scan['risk_score']}% ({scan['risk_level']})</b></font>", body_style)],
            [Paragraph("<b>Dispatch Date:</b>", body_style), Paragraph(str(scan['created_at']), body_style)],
        ]
        meta_table = Table(meta_data, colWidths=[120, 420])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

        elements.append(Paragraph("AI Engine Rationale & Protocol", heading2_style))
        elements.append(Paragraph(f"<b>Rationale:</b> {ai_explanation}", body_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(f"<b>Constraints & Protocol:</b> {recommendations}", body_style))
        elements.append(Spacer(1, 10))

        elements.append(Paragraph("Signal Extraction Metrics", heading2_style))
        scan_res = scan.get("scan_result", {})
        metrics_data = [["Metric", "Value"]]
        for k, v in scan_res.items():
            if k not in ["vt_results", "exiftool_results"]:
                metrics_data.append([str(k), str(v)])

        if len(metrics_data) > 1:
            metrics_table = Table(metrics_data, colWidths=[240, 300])
            metrics_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (1,0), colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (0,0), (1,0), colors.white),
                ('FONTNAME', (0,0), (1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (1,0), 9),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#f1f5f9')),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            elements.append(metrics_table)
            elements.append(Spacer(1, 10))

        exif = scan_res.get("exiftool_results", {})
        indicators = exif.get("stego_indicators", [])
        if indicators:
            elements.append(Paragraph("ExifTool Stego & Object Indicators", heading2_style))
            for ind in indicators:
                elements.append(Paragraph(f"• <b>{ind.get('type','Anomalous')} ({ind.get('severity','MEDIUM')}):</b> {ind.get('description','')}", body_style))
            elements.append(Spacer(1, 10))

        metadata_dict = exif.get("metadata", {})
        if metadata_dict:
            elements.append(Paragraph("ExifTool Raw Metadata Tags", heading2_style))
            table_rows = [["Tag Name", "Value"]]
            for k, val in metadata_dict.items():
                table_rows.append([Paragraph(f"<b>{k}</b>", small_style), Paragraph(str(val), small_style)])

            tag_table = Table(table_rows, colWidths=[200, 340])
            tag_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (1,0), colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (0,0), (1,0), colors.white),
                ('FONTNAME', (0,0), (1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (1,0), 9),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0,0), (-1,-1), 4),
            ]))
            elements.append(tag_table)

        doc.build(elements)
        buffer.seek(0)

        headers = {
            'Content-Disposition': f'attachment; filename="stego_report_{scan_id}.pdf"'
        }
        return StreamingResponse(buffer, media_type="application/pdf", headers=headers)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# ──────────────────────────────────────────────
# Dedicated ExifTool Metadata Exports
# ──────────────────────────────────────────────
@router.get("/threat-reports/{scan_id}/export-exiftool-csv")
async def export_exiftool_csv(scan_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        res = supabase.table("scan_history").select("*").eq("id", scan_id).eq("user_id", user_id).execute()
        if not res.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
        scan = res.data[0]
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(["EXIFTOOL OBJECT METADATA & STEGO ANALYSIS REPORT"])
        writer.writerow([])
        writer.writerow(["Report ID", scan["id"]])
        writer.writerow(["File Name", scan["file_name"]])
        writer.writerow(["File Type", scan["file_type"]])
        writer.writerow(["Scan Date", scan["created_at"]])
        writer.writerow([])
        
        exif = scan.get("scan_result", {}).get("exiftool_results", {})
        indicators = exif.get("stego_indicators", [])
        
        writer.writerow(["STEGO INDICATORS"])
        if indicators:
            writer.writerow(["Indicator Type", "Severity", "Description"])
            for ind in indicators:
                writer.writerow([ind.get("type"), ind.get("severity"), ind.get("description")])
        else:
            writer.writerow(["No metadata/object stego indicators found."])
            
        writer.writerow([])
        writer.writerow(["RAW EXIFTOOL METADATA TAGS"])
        writer.writerow(["Tag / Field", "Value"])
        metadata_dict = exif.get("metadata", {})
        for tag, val in metadata_dict.items():
            writer.writerow([tag, val])
            
        output.seek(0)
        headers = {
            'Content-Disposition': f'attachment; filename="exiftool_analysis_{scan_id}.csv"'
        }
        return StreamingResponse(io.BytesIO(output.getvalue().encode("utf-8")), media_type="text/csv", headers=headers)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/threat-reports/{scan_id}/export-exiftool-json")
async def export_exiftool_json(scan_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        res = supabase.table("scan_history").select("*").eq("id", scan_id).eq("user_id", user_id).execute()
        if not res.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
        scan = res.data[0]
        exif = scan.get("scan_result", {}).get("exiftool_results", {})
        
        exif_report = {
            "title": "ExifTool Object Metadata & Stego Analysis Report",
            "report_id": scan["id"],
            "file_name": scan["file_name"],
            "file_type": scan["file_type"],
            "scan_date": scan["created_at"],
            "exiftool_results": exif
        }
        
        import json
        json_bytes = json.dumps(exif_report, indent=2).encode("utf-8")
        headers = {
            'Content-Disposition': f'attachment; filename="exiftool_analysis_{scan_id}.json"'
        }
        return StreamingResponse(io.BytesIO(json_bytes), media_type="application/json", headers=headers)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/threat-reports/{scan_id}/export-exiftool-pdf")
async def export_exiftool_pdf(scan_id: str, user_id: str = Depends(get_current_user_id)):
    try:
        res = supabase.table("scan_history").select("*").eq("id", scan_id).eq("user_id", user_id).execute()
        if not res.data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
        scan = res.data[0]
        exif = scan.get("scan_result", {}).get("exiftool_results", {})

        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'DocTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=18, textColor=colors.HexColor('#0f172a'), spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            'DocSubTitle', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#0284c7'), spaceAfter=8
        )
        heading2_style = ParagraphStyle(
            'Heading2Custom', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=12, textColor=colors.HexColor('#0f172a'), spaceBefore=10, spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyCustom', parent=styles['Normal'], fontName='Helvetica', fontSize=9, leading=13, textColor=colors.HexColor('#334155')
        )
        small_style = ParagraphStyle(
            'SmallCustom', parent=styles['Normal'], fontName='Helvetica', fontSize=8, leading=11, textColor=colors.HexColor('#334155')
        )

        elements = []
        elements.append(Paragraph("EXIFTOOL OBJECT METADATA & STEGO ANALYSIS", subtitle_style))
        elements.append(Paragraph("Deep Forensic Metadata Inspection Report", title_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=12))

        meta_data = [
            [Paragraph("<b>Report ID:</b>", body_style), Paragraph(str(scan['id']), body_style)],
            [Paragraph("<b>File Name:</b>", body_style), Paragraph(str(scan['file_name']), body_style)],
            [Paragraph("<b>Format Category:</b>", body_style), Paragraph(str(scan['file_type']).upper(), body_style)],
            [Paragraph("<b>Dispatch Date:</b>", body_style), Paragraph(str(scan['created_at']), body_style)],
        ]
        meta_table = Table(meta_data, colWidths=[120, 420])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

        indicators = exif.get("stego_indicators", [])
        elements.append(Paragraph("Stego & Object Indicators", heading2_style))
        if indicators:
            for ind in indicators:
                elements.append(Paragraph(f"• <b>{ind.get('type','Anomalous')} ({ind.get('severity','MEDIUM')}):</b> {ind.get('description','')}", body_style))
        else:
            elements.append(Paragraph("✅ No metadata or object stego indicators found.", body_style))
        elements.append(Spacer(1, 10))

        metadata_dict = exif.get("metadata", {})
        if metadata_dict:
            elements.append(Paragraph("Raw ExifTool Metadata Tags", heading2_style))
            table_rows = [["Tag Name", "Value"]]
            for k, val in metadata_dict.items():
                table_rows.append([Paragraph(f"<b>{k}</b>", small_style), Paragraph(str(val), small_style)])

            tag_table = Table(table_rows, colWidths=[200, 340])
            tag_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (1,0), colors.HexColor('#0f172a')),
                ('TEXTCOLOR', (0,0), (1,0), colors.white),
                ('FONTNAME', (0,0), (1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (1,0), 9),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0,0), (-1,-1), 4),
            ]))
            elements.append(tag_table)

        doc.build(elements)
        buffer.seek(0)
        headers = {
            'Content-Disposition': f'attachment; filename="exiftool_analysis_{scan_id}.pdf"'
        }
        return StreamingResponse(buffer, media_type="application/pdf", headers=headers)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
