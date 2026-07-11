import hashlib
import requests
import time
import os
from typing import Optional, Dict, Any
from app.core.config import settings

API_KEY = getattr(settings, "VIRUSTOTAL_API_KEY", "6310a37664cc7685d55e3401d2149027ebd4d305f51ccae740c3c2ec18709da8")
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {
    "x-apikey": API_KEY
}

def get_bytes_hash(file_bytes: bytes, algo: str = "sha256") -> str:
    """Compute the hash of file bytes (default sha256)."""
    h = hashlib.new(algo)
    h.update(file_bytes)
    return h.hexdigest()

def get_report_by_hash(file_hash: str) -> Optional[Dict[str, Any]]:
    """Check if VirusTotal already has a report for this file hash."""
    url = f"{BASE_URL}/files/{file_hash}"
    try:
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return None  # No existing report
        else:
            resp.raise_for_status()
    except Exception as e:
        print(f"[ERROR] VirusTotal hash report fetch failed: {e}")
        return None

def upload_file_bytes(file_bytes: bytes, file_name: str) -> Dict[str, Any]:
    """Upload file bytes to VirusTotal for scanning."""
    url = f"{BASE_URL}/files"
    file_size = len(file_bytes)
    
    # Files > 32MB need a special upload URL
    if file_size > 32 * 1024 * 1024:
        upload_url_resp = requests.get(f"{BASE_URL}/files/upload_url", headers=HEADERS)
        upload_url_resp.raise_for_status()
        url = upload_url_resp.json()["data"]

    files = {"file": (file_name, file_bytes)}
    resp = requests.post(url, headers=HEADERS, files=files)
    resp.raise_for_status()
    return resp.json()

def poll_analysis(analysis_id: str, wait_seconds: int = 10, max_tries: int = 15) -> Dict[str, Any]:
    """Poll VirusTotal for analysis completion."""
    url = f"{BASE_URL}/analyses/{analysis_id}"
    for attempt in range(max_tries):
        resp = requests.get(url, headers=HEADERS)
        resp.raise_for_status()
        data = resp.json()
        status = data["data"]["attributes"]["status"]
        print(f"[INFO] VirusTotal Analysis check {attempt + 1}: status = {status}")
        if status == "completed":
            return data
        time.sleep(wait_seconds)
    raise TimeoutError("VirusTotal analysis did not complete in time.")

def extract_summary(attributes: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a clean, serializable summary of the VirusTotal scan results."""
    stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    results = attributes.get("last_analysis_results") or attributes.get("results") or {}
    
    malicious_engines = []
    if stats.get("malicious", 0) > 0:
        for engine, result in results.items():
            if result.get("category") == "malicious":
                malicious_engines.append({
                    "engine": engine,
                    "result": result.get("result")
                })
                
    return {
        "stats": stats,
        "malicious_engines": malicious_engines,
        "reputation": attributes.get("reputation", 0),
        "type_description": attributes.get("type_description", "unknown"),
        "meaningful_name": attributes.get("meaningful_name", "unknown")
    }

def scan_file_bytes(file_bytes: bytes, file_name: str) -> Dict[str, Any]:
    """Coordinates the hash check and scanning logic for VirusTotal."""
    file_hash = get_bytes_hash(file_bytes)
    print(f"[INFO] Checking VirusTotal for SHA256: {file_hash}")
    
    report = get_report_by_hash(file_hash)
    if report:
        print("[INFO] Existing VirusTotal report found.")
        attributes = report["data"]["attributes"]
        return {
            "status": "success",
            "source": "cache",
            "sha256": file_hash,
            "data": extract_summary(attributes)
        }
    
    print("[INFO] No existing VirusTotal report. Uploading file for scan...")
    try:
        upload_resp = upload_file_bytes(file_bytes, file_name)
        analysis_id = upload_resp["data"]["id"]
        print(f"[INFO] Uploaded. Analysis ID: {analysis_id}. Polling...")
        result = poll_analysis(analysis_id)
        attributes = result["data"]["attributes"]
        
        # Once analysis is complete, fetch the updated file report to get the full stats
        file_report = get_report_by_hash(file_hash)
        if file_report:
            attributes = file_report["data"]["attributes"]
            
        return {
            "status": "success",
            "source": "live_scan",
            "sha256": file_hash,
            "data": extract_summary(attributes)
        }
    except Exception as e:
        print(f"[ERROR] Live VirusTotal scan failed: {e}")
        return {
            "status": "error",
            "message": f"VirusTotal scanning failed: {str(e)}",
            "sha256": file_hash,
            "data": None
        }
