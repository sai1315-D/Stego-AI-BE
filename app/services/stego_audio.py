import io
import librosa
import numpy as np
import soundfile as sf
import math

class AudioStegoDetector:
    @staticmethod
    def analyze(file_bytes: bytes) -> dict:
        """
        Analyze an audio file (WAV, MP3) for hidden payload anomalies.
        Uses Librosa for MFCCs, Spectral Centroid, and Frequency analysis,
        along with direct raw PCM LSB entropy evaluation.
        """
        # Load audio data from memory
        # We try using soundfile first, fallback to librosa (which might use audioread/ffmpeg)
        try:
            audio_io = io.BytesIO(file_bytes)
            y, sr = sf.read(audio_io)
            # If multi-channel, convert to mono
            if len(y.shape) > 1:
                y = np.mean(y, axis=1)
        except Exception:
            # Fallback to librosa.load via bytes using a temp file-like structure or soundfile directly
            try:
                audio_io = io.BytesIO(file_bytes)
                y, sr = librosa.load(audio_io, sr=None)
            except Exception as e:
                raise ValueError(f"Failed to decode audio file. Error: {str(e)}")

        if y is None or len(y) == 0:
            raise ValueError("Empty or corrupt audio sample.")

        # 1. Feature Extraction using Librosa
        # Spectral Centroid: Represents the "brightness" of a sound.
        # Stego content usually injects high-frequency noise, which pushes the centroid higher.
        spectral_centroids = librosa.feature.spectral_centroid(y=y, sr=sr)[0]
        mean_centroid = float(np.mean(spectral_centroids))
        std_centroid = float(np.std(spectral_centroids))
        
        # Spectral Rolloff: Frequency below which 85% of spectral energy lies.
        spectral_rolloff = librosa.feature.spectral_rolloff(y=y, sr=sr, roll_percent=0.85)[0]
        mean_rolloff = float(np.mean(spectral_rolloff))

        # MFCCs (Mel-frequency cepstral coefficients)
        # Steganography tends to alter the higher-order MFCCs (coefficients 10-20),
        # which capture micro-details of the spectral envelope (noise patterns).
        mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=20)
        mean_mfccs = [float(np.mean(coef)) for coef in mfccs]
        std_mfccs = [float(np.std(coef)) for coef in mfccs]
        
        # Calculate high-frequency energy ratio: Stego injects high-frequency white noise.
        # Check standard deviation of coefficients 12-20 vs 1-10
        high_coef_std = np.mean(std_mfccs[12:])
        low_coef_std = np.mean(std_mfccs[:12])
        mfcc_ratio = float(high_coef_std / (low_coef_std + 1e-6))

        # 2. Raw LSB Heuristic (Hidden Signal Detection)
        # Convert float samples back to quantized 16-bit integers to inspect the exact LSB plane
        y_int = np.int16(y * 32767)
        lsb_bits = y_int & 1
        
        # Calculate LSB bits ratio of 1s
        lsb_ones = np.sum(lsb_bits)
        lsb_ones_ratio = float(lsb_ones / len(lsb_bits))
        
        # Calculate LSB bits entropy (should be close to 1.0 for random data)
        prob_1 = lsb_ones_ratio
        prob_0 = 1.0 - lsb_ones_ratio
        if prob_1 > 0 and prob_0 > 0:
            lsb_entropy = - (prob_1 * math.log2(prob_1) + prob_0 * math.log2(prob_0))
        else:
            lsb_entropy = 0.0

        # LSB correlation check along audio stream (stego data is uncorrelated)
        lsb_diff = np.abs(lsb_bits[:-1] - lsb_bits[1:])
        audio_lsb_correlation = float(1.0 - np.mean(lsb_diff))

        # 3. Decision Score System
        # Heuristic rules:
        # - High LSB entropy (> 0.998)
        # - High MFCC Ratio (representing micro-noise anomalies in high coefficients)
        # - High Spectral Centroid variance or high frequency residuals
        score = 0.0
        
        # LSB Entropy
        if lsb_entropy > 0.998:
            score += 35 * (lsb_entropy - 0.998) / 0.002
        elif lsb_entropy < 0.95:
            score -= 10
            
        # Audio LSB Correlation (Natural speech/music has LSB correlation > 0.4; noise is around 0.5 diff -> 0.5 correlation)
        # Stego LSBs tend to be completely random, yielding correlation very close to 0.50
        if abs(audio_lsb_correlation - 0.50) < 0.01:
            score += 30
        elif audio_lsb_correlation > 0.6:
            score -= 15

        # MFCC high-frequency ratio (elevated micro-noise indicates stego modification)
        if mfcc_ratio > 1.2:
            score += 25 * (mfcc_ratio - 1.2) / 0.5
        elif mfcc_ratio < 0.8:
            score -= 10

        # Normalize score
        risk_score = max(0, min(100, int(score + 10)))

        if risk_score <= 30:
            risk_level = "SAFE"
            description = "No steganography detected. Audio spectrum shows natural frequency decay and standard MFCC envelope coefficients."
        elif risk_score <= 70:
            risk_level = "SUSPICIOUS"
            description = "Minor frequency deviations and high-frequency spectral noise detected. The audio LSB profile is highly randomized."
        else:
            risk_level = "DANGEROUS"
            description = "High risk of steganographic content. Extremely high LSB entropy and altered higher-order MFCC structures indicate a hidden data channel."

        return {
            "file_name": "",
            "file_type": "audio",
            "threat_probability": risk_score / 100.0,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "description": description,
            "metrics": {
                "lsb_ones_ratio": round(lsb_ones_ratio, 4),
                "lsb_entropy": round(lsb_entropy, 4),
                "audio_lsb_correlation": round(audio_lsb_correlation, 4),
                "mean_centroid": round(mean_centroid, 2),
                "std_centroid": round(std_centroid, 2),
                "mean_rolloff": round(mean_rolloff, 2),
                "mfcc_ratio": round(mfcc_ratio, 4)
            }
        }
