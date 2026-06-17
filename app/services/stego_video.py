import cv2
import numpy as np
import tempfile
import os
import math
from app.services.stego_image import ImageStegoDetector

class VideoStegoDetector:
    @staticmethod
    def analyze(file_bytes: bytes) -> dict:
        """
        Analyze a video file (MP4, AVI) for hidden stego payloads.
        Saves the file temporarily to read frames via OpenCV, extracts frame metrics,
        and evaluates temporal variations.
        """
        # Create a temporary file to load into cv2.VideoCapture
        temp_dir = tempfile.gettempdir()
        temp_file_path = os.path.join(temp_dir, next(tempfile._get_candidate_names()) + ".tmp_video")
        
        try:
            with open(temp_file_path, "wb") as f:
                f.write(file_bytes)
                
            cap = cv2.VideoCapture(temp_file_path)
            if not cap.isOpened():
                raise ValueError("Could not open video file. Format may be unsupported or corrupt.")
                
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps = cap.get(cv2.CAP_PROP_FPS)
            
            # Step size to sample up to 15 frames uniformly across the video to prevent timeouts
            sample_count = min(15, total_frames) if total_frames > 0 else 1
            step = max(1, total_frames // sample_count)
            
            frame_metrics = []
            frame_index = 0
            read_count = 0
            
            while cap.isOpened() and read_count < sample_count:
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_index)
                ret, frame = cap.read()
                if not ret:
                    break
                
                # Analyze individual frame as an image
                # Encode frame back to JPEG bytes to pass to ImageStegoDetector
                _, buffer = cv2.imencode('.jpg', frame)
                try:
                    res = ImageStegoDetector.analyze(buffer.tobytes())
                    frame_metrics.append(res)
                except Exception:
                    pass
                
                frame_index += step
                read_count += 1
                
            cap.release()
        finally:
            # Safely clean up the temp file
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
                
        if not frame_metrics:
            raise ValueError("Failed to extract scan frames from video sample.")
            
        # 1. Temporal Analysis
        # Extract individual metric arrays
        scores = [m["risk_score"] for m in frame_metrics]
        lsb_entropies = [m["metrics"]["lsb_entropy"] for m in frame_metrics]
        lsb_correlations = [m["metrics"]["lsb_correlation"] for m in frame_metrics]
        chi_squares = [m["metrics"]["chi_square_stat"] for m in frame_metrics]
        
        avg_score = float(np.mean(scores))
        max_score = float(np.max(scores))
        
        # Temporal variance: stego hidden in specific frames leads to high variance in entropy and chi-square
        entropy_variance = float(np.var(lsb_entropies))
        correlation_variance = float(np.var(lsb_correlations))
        
        # 2. Decision System
        # Combine frame risk scores and temporal variations.
        # High average frame risk + high variance indicating selective payload embedding.
        threat_score = avg_score
        
        # Temporal anomaly detection: if there is high variance in correlation, it is suspicious
        if correlation_variance > 0.005:
            threat_score += 15
            
        if entropy_variance > 0.001:
            threat_score += 10
            
        risk_score = max(0, min(100, int(threat_score)))
        
        if risk_score <= 30:
            risk_level = "SAFE"
            description = "No video steganography detected. Inter-frame temporal dynamics and LSB noise distribution are within normal parameters."
        elif risk_score <= 70:
            risk_level = "SUSPICIOUS"
            description = "Minor inter-frame statistical fluctuations detected. Certain frames show elevated LSB randomness and low spatial correlation."
        else:
            risk_level = "DANGEROUS"
            description = "High threat level. Temporal analysis reveals systematic, non-uniform anomalies in LSB bit streams across video frames, indicating a multi-frame hidden payload."
            
        return {
            "file_name": "",
            "file_type": "video",
            "threat_probability": risk_score / 100.0,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "description": description,
            "metrics": {
                "total_frames": total_frames,
                "fps": round(fps, 2),
                "avg_frame_score": round(avg_score, 2),
                "max_frame_score": round(max_score, 2),
                "entropy_variance": round(entropy_variance, 6),
                "correlation_variance": round(correlation_variance, 6),
                "mean_chi_square": round(float(np.mean(chi_squares)), 2)
            }
        }
