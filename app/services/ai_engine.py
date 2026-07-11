import os
import joblib
import numpy as np
from app.services.stego_image import ImageStegoDetector
from app.services.stego_audio import AudioStegoDetector
from app.services.stego_video import VideoStegoDetector
from app.services.stego_document import DocumentStegoDetector
from app.services.model_wrapper import StegoMultiClassifier

# Path to local ML model weights if available
MODEL_PATH = os.path.join(os.path.dirname(__file__), "stego_classifier.joblib")

class AIEngine:
    def __init__(self):
        self.model = None
        # Attempt to load pretrained model if it exists
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
            except Exception:
                self.model = None

    def analyze_file(self, file_bytes: bytes, file_name: str, file_type: str) -> dict:
        """
        Analyze file using the specific format analyzer and apply final machine learning/heuristic scoring.
        """
        file_type = file_type.lower()
        
        # Route to respective DSP feature extractors
        if file_type == "image":
            res = ImageStegoDetector.analyze(file_bytes)
        elif file_type == "audio":
            res = AudioStegoDetector.analyze(file_bytes)
        elif file_type == "video":
            res = VideoStegoDetector.analyze(file_bytes, file_name)
        elif file_type == "document":
            res = DocumentStegoDetector.analyze(file_bytes, file_name)
        else:
            raise ValueError(f"Unsupported file type: {file_type}")

        # Update file name in the response
        res["file_name"] = file_name

        # If a trained scikit-learn model is present, refine the heuristic score.
        # Otherwise, the DSP heuristic scoring will be utilized.
        if self.model:
            try:
                # Example: Use extracted metrics as features for the classifier
                metrics = res["metrics"]
                feature_vector = np.array(list(metrics.values())).reshape(1, -1)
                ml_prob = float(self.model.predict_proba(feature_vector)[0][1])
                
                # Update threat probability and score with ML prediction (weighted 70% ML, 30% DSP)
                dsp_prob = res["threat_probability"]
                combined_prob = (ml_prob * 0.7) + (dsp_prob * 0.3)
                
                risk_score = int(combined_prob * 100)
                res["threat_probability"] = combined_prob
                res["risk_score"] = risk_score
                
                # Reclassify Risk Levels based on updated score
                if risk_score <= 30:
                    res["risk_level"] = "SAFE"
                elif risk_score <= 70:
                    res["risk_level"] = "SUSPICIOUS"
                else:
                    res["risk_level"] = "DANGEROUS"
            except Exception:
                # Fallback to pure DSP results if features mismatch the model shape
                pass

        return res

# Global AI Engine instance
ai_engine = AIEngine()
