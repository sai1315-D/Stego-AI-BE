import cv2
import numpy as np
import math

class ImageStegoDetector:
    @staticmethod
    def analyze(file_bytes: bytes) -> dict:
        """
        Analyze an image for hidden payloads using LSB, Chi-Square, Shannon Entropy, and Noise Residual.
        """
        # Load image using OpenCV
        nparr = np.frombuffer(file_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            raise ValueError("Invalid image file or format not supported by OpenCV.")
            
        # Basic properties
        height, width, channels = img.shape
        total_pixels = height * width
        
        # 1. LSB Bit Density and Statistics
        # We extract LSB of the red channel (often used for LSB steg) and analyze its statistical properties.
        # Clean images have LSBs that correlate with the visual structures, while random encrypted data looks like noise.
        red_channel = img[:, :, 2]
        lsb_plane = red_channel & 1
        
        # Calculate LSB ratio of 1s vs 0s (should be close to 0.5 for random data, but visually correlated for clean images)
        lsb_ones = np.sum(lsb_plane)
        lsb_ones_ratio = float(lsb_ones / total_pixels)
        
        # Spatial correlation in the LSB plane: measure if adjacent LSBs are correlated.
        # Clean images show higher spatial correlation in the LSB than stego images.
        lsb_diff_h = np.abs(lsb_plane[:, :-1] - lsb_plane[:, 1:])
        lsb_diff_v = np.abs(lsb_plane[:-1, :] - lsb_plane[1:, :])
        lsb_correlation = float(1.0 - (np.mean(lsb_diff_h) + np.mean(lsb_diff_v)) / 2.0)
        
        # 2. Chi-Square (X^2) Steg-Analysis (POV Attack)
        # We look at the Pairs of Values (PoVs): adjacent grey levels (e.g. 2k and 2k+1)
        # In a natural image, these have asymmetric frequencies. LSB embedding makes them symmetrical.
        hist, _ = np.histogram(red_channel, bins=256, range=(0, 256))
        
        chi_square_stat = 0.0
        degrees_of_freedom = 0
        
        for i in range(0, 256, 2):
            y_obs = hist[i]  # observed frequency
            y_obs_next = hist[i+1]
            
            y_exp = (y_obs + y_obs_next) / 2.0  # expected frequency under stego hypothesis
            
            if y_exp > 0:
                chi_square_stat += ((y_obs - y_exp) ** 2) / y_exp
                degrees_of_freedom += 1
        
        # 3. Shannon Entropy of the LSB plane
        # Measures the amount of information in the LSB. For encrypted payloads, entropy approaches 1.0.
        prob_1 = lsb_ones_ratio
        prob_0 = 1.0 - lsb_ones_ratio
        if prob_1 > 0 and prob_0 > 0:
            lsb_entropy = - (prob_1 * math.log2(prob_1) + prob_0 * math.log2(prob_0))
        else:
            lsb_entropy = 0.0
            
        # Shannon Entropy of the overall red channel
        hist_prob = hist / total_pixels
        overall_entropy = -sum([p * math.log2(p) for p in hist_prob if p > 0])
        
        # 4. Noise Pattern Analysis (Laplacian High-Pass Residual)
        # Apply a Laplacian filter to extract the noise residual of the image.
        # Highly high-pass filtered images contain LSB stego patterns that stand out.
        laplacian = cv2.Laplacian(red_channel, cv2.CV_64F)
        noise_variance = float(np.var(laplacian))
        
        # Formulate Stego Probability
        # Heuristic scoring based on DSP metrics:
        # - LSB correlation: Lower correlation (looks like noise) increases threat score.
        # - LSB entropy: Close to 1.0 increases threat score.
        # - Chi-Square: Lower Chi-Square statistic indicates flatter PoVs (higher likelihood of LSB steganography).
        # - LSB ones ratio: Balanced 1s and 0s (approx 0.5) is common for encrypted stego files.
        
        # Score calculation parameters
        score = 0.0
        
        # Heuristic rules:
        # 1. LSB Correlation check (Clean image typically has correlation > 0.45; stego approaches 0.3)
        if lsb_correlation < 0.4:
            score += 35 * (0.4 - lsb_correlation) / 0.1
        elif lsb_correlation > 0.48:
            score -= 10
            
        # 2. LSB Entropy check (Stego typically has LSB entropy > 0.999)
        if lsb_entropy > 0.995:
            score += 30 * (lsb_entropy - 0.995) / 0.005
            
        # 3. Chi-Square Statistic check (If extremely low under stego hypothesis, high probability)
        # Lower chi_square_stat means the distribution fits the stego POV hypothesis perfectly
        if chi_square_stat < 100.0:
            score += 25 * (100.0 - chi_square_stat) / 100.0
        elif chi_square_stat > 1000.0:
            score -= 15
            
        # Normalize score
        risk_score = max(0, min(100, int(score + 15))) # base score adjustment
        
        # Risk level classification
        if risk_score <= 30:
            risk_level = "SAFE"
            description = "No steganography detected. The pixel layout and bit correlation follow natural distribution patterns."
        elif risk_score <= 70:
            risk_level = "SUSPICIOUS"
            description = "Minor statistical anomalies detected. The image shows lower-than-normal LSB bit correlation and slightly flattened color distribution."
        else:
            risk_level = "DANGEROUS"
            description = "High probability of steganographic content. Chi-Square POV testing reveals systematic LSB alteration patterns indicative of an encrypted payload."
            
        return {
            "file_name": "",
            "file_type": "image",
            "threat_probability": risk_score / 100.0,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "description": description,
            "metrics": {
                "lsb_ones_ratio": round(lsb_ones_ratio, 4),
                "lsb_correlation": round(lsb_correlation, 4),
                "lsb_entropy": round(lsb_entropy, 4),
                "overall_entropy": round(overall_entropy, 4),
                "chi_square_stat": round(chi_square_stat, 2),
                "noise_variance": round(noise_variance, 2)
            }
        }
