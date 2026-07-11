import os
import subprocess
import tempfile
import json
import traceback

class ExifToolService:
    def __init__(self):
        # Path to exiftool.exe inside backend folder
        self.exiftool_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "exiftool.exe"
        )
        # Fallback to system exiftool if local is not present
        if not os.path.exists(self.exiftool_path):
            self.exiftool_path = "exiftool"

    def analyze_metadata(self, file_bytes: bytes, file_name: str) -> dict:
        """
        Run ExifTool on file bytes, extract all metadata, and check for steganography indicators:
        - Trailer/trailing data warnings (common for hidden files/zip archives appended after images).
        - MIME/FileType mismatch (suspicious extensions).
        - Unusually large or structured comments/metadata.
        """
        result = {
            "status": "success",
            "metadata": {},
            "warnings": [],
            "stego_indicators": [],
            "risk_score_impact": 0
        }
        
        # Write bytes to a temporary file for ExifTool to scan
        suffix = os.path.splitext(file_name)[1] if file_name else ""
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            temp_file.write(file_bytes)
            temp_path = temp_file.name
            
        try:
            # Command to run exiftool in JSON output mode
            # -G adds group names (e.g. EXIF, XMP, File, Composite)
            cmd = [self.exiftool_path, "-json", "-G", temp_path]
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore"
            )
            
            if proc.returncode == 0:
                output = proc.stdout.strip()
                if output:
                    parsed_json = json.loads(output)
                    if parsed_json and isinstance(parsed_json, list):
                        # Exiftool returns a list of dicts (one per file)
                        raw_meta = parsed_json[0]
                        # Clean up path details
                        cleaned_meta = {}
                        for key, val in raw_meta.items():
                            # Remove temp file path from key names or values if any
                            clean_key = key.split(":")[-1] if ":" in key else key
                            # Skip internal file path tag
                            if clean_key.lower() in ["sourcefile", "directory", "filepath", "filename"]:
                                continue
                            cleaned_meta[key] = val
                        
                        result["metadata"] = cleaned_meta
            else:
                result["status"] = "error"
                result["warnings"].append(f"ExifTool returned code {proc.returncode}: {proc.stderr}")
                
        except Exception as e:
            result["status"] = "error"
            result["warnings"].append(f"ExifTool run failed: {str(e)}")
            traceback.print_exc()
        finally:
            # Delete temp file
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
                    
        # --- Stego Assessment based on Metadata ---
        metadata = result["metadata"]
        
        # 1. Check for ExifTool warnings (like Trailer data)
        # ExifTool tags warnings in "File:Warning" or "Composite:Warning" etc.
        warnings_found = []
        for key, val in metadata.items():
            if "warning" in key.lower():
                warnings_found.append(str(val))
                
        for warn in warnings_found:
            result["warnings"].append(warn)
            warn_lower = warn.lower()
            if "trailer" in warn_lower or "after end of" in warn_lower or "extra bytes" in warn_lower:
                result["stego_indicators"].append({
                    "type": "APPENDED_TRAILER",
                    "severity": "HIGH",
                    "description": f"ExifTool warning: {warn}. Indicates data (possibly hidden payload) appended after the standard file EOF."
                })
                result["risk_score_impact"] += 45
            elif "corrupt" in warn_lower or "invalid" in warn_lower:
                result["stego_indicators"].append({
                    "type": "CORRUPTED_METADATA",
                    "severity": "MEDIUM",
                    "description": f"ExifTool warning: {warn}. Metadata structure is broken or malformed."
                })
                result["risk_score_impact"] += 20
                
        # 2. Check for extension vs magic bytes mismatch
        expected_type = metadata.get("File:FileType", metadata.get("FileType", ""))
        if expected_type:
            # Get extension
            ext = os.path.splitext(file_name)[1].lower().replace(".", "").strip()
            # Mapping common extensions to FileType names
            ext_map = {
                "jpg": "JPEG", "jpeg": "JPEG",
                "png": "PNG",
                "gif": "GIF",
                "mp4": "MP4",
                "pdf": "PDF",
                "zip": "ZIP", "rar": "RAR", "7z": "7Z"
            }
            if ext in ext_map and expected_type.upper() != ext_map[ext]:
                result["stego_indicators"].append({
                    "type": "MIME_MISMATCH",
                    "severity": "HIGH",
                    "description": f"File extension is '.{ext}' but magic bytes header indicates it is a {expected_type} file. Attempted file signature spoofing."
                })
                result["risk_score_impact"] += 50
                
        # 3. Scan textual metadata fields for unusually large values (stego text carrier)
        suspicious_tags = [
            "comment", "description", "usercomment", "copyright", "artist", "software",
            "xpcomment", "subject"
        ]
        for key, val in metadata.items():
            clean_key = key.split(":")[-1].lower() if ":" in key else key.lower()
            if clean_key in suspicious_tags and isinstance(val, str):
                # If a comment/description field is > 2000 chars, it's suspicious
                if len(val) > 2000:
                    result["stego_indicators"].append({
                        "type": "MASSIVE_TEXT_TAG",
                        "severity": "MEDIUM",
                        "description": f"Metadata field '{key}' contains unusually long text ({len(val)} chars). Potential carrier of hidden encrypted stego text."
                    })
                    result["risk_score_impact"] += 25
                # Check for base64-like patterns or high entropy in description
                if len(val) > 100 and val.endswith("=") and not " " in val:
                    result["stego_indicators"].append({
                        "type": "BASE64_PAYLOAD",
                        "severity": "HIGH",
                        "description": f"Metadata field '{key}' appears to contain a raw Base64 encoded payload instead of human readable text."
                    })
                    result["risk_score_impact"] += 35
                    
        return result

exiftool_service = ExifToolService()
