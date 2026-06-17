import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from app.services.model_wrapper import StegoMultiClassifier

def generate_synthetic_data(feature_dim: int, num_samples: int = 1000):
    """
    Generate synthetic safe and stego feature vectors matching the expected
    distributions for each file type / feature dimension.
    """
    np.random.seed(42)
    half = num_samples // 2
    
    # Initialize feature arrays
    X = np.zeros((num_samples, feature_dim))
    y = np.zeros(num_samples)
    y[half:] = 1 # 0 = Safe, 1 = Stego/Threat
    
    if feature_dim == 2:
        # Plain Text (TXT): [zero_width_chars, whitespace_encoded_lines]
        # Safe
        X[:half, 0] = np.random.poisson(lam=0.1, size=half) # zero-width count
        X[:half, 1] = np.random.poisson(lam=0.2, size=half) # whitespace line count
        # Stego
        X[half:, 0] = np.random.randint(5, 50, size=half)
        X[half:, 1] = np.random.randint(3, 15, size=half)
        
    elif feature_dim == 3:
        # Word (DOCX): [hidden_runs, zero_width_chars, large_comments_property]
        # Safe
        X[:half, 0] = np.random.poisson(lam=0.05, size=half)
        X[:half, 1] = np.random.poisson(lam=0.1, size=half)
        X[:half, 2] = np.random.poisson(lam=5, size=half)
        # Stego
        X[half:, 0] = np.random.randint(2, 20, size=half)
        X[half:, 1] = np.random.randint(10, 100, size=half)
        X[half:, 2] = np.random.choice([0, 1000, 2000, 5000], size=half)
        
    elif feature_dim == 4:
        # PDF: [appended_bytes, custom_metadata_fields, zero_width_chars, whitespace_patterns]
        # Safe
        X[:half, 0] = np.random.poisson(lam=2, size=half)
        X[:half, 1] = np.random.poisson(lam=0.5, size=half)
        X[:half, 2] = np.random.poisson(lam=0.1, size=half)
        X[:half, 3] = np.random.poisson(lam=0.2, size=half)
        # Stego
        X[half:, 0] = np.random.randint(100, 8000, size=half)
        X[half:, 1] = np.random.randint(3, 12, size=half)
        X[half:, 2] = np.random.randint(10, 200, size=half)
        X[half:, 3] = np.random.randint(3, 25, size=half)
        
    elif feature_dim == 6:
        # Image: [lsb_ones_ratio, lsb_correlation, lsb_entropy, overall_entropy, chi_square_stat, noise_variance]
        # Safe
        X[:half, 0] = np.random.normal(0.5, 0.04, size=half)       # lsb_ones_ratio
        X[:half, 1] = np.random.normal(0.52, 0.05, size=half)      # lsb_correlation
        X[:half, 2] = np.random.normal(0.97, 0.02, size=half)      # lsb_entropy
        X[:half, 3] = np.random.normal(7.1, 0.4, size=half)        # overall_entropy
        X[:half, 4] = np.random.normal(550.0, 120.0, size=half)    # chi_square_stat
        X[:half, 5] = np.random.normal(12.0, 4.0, size=half)       # noise_variance
        
        # Stego
        X[half:, 0] = np.random.normal(0.5, 0.003, size=half)      # lsb_ones_ratio
        X[half:, 1] = np.random.normal(0.33, 0.02, size=half)      # lsb_correlation
        X[half:, 2] = np.random.normal(0.9997, 0.0002, size=half)  # lsb_entropy
        X[half:, 3] = np.random.normal(7.3, 0.3, size=half)        # overall_entropy
        X[half:, 4] = np.random.normal(35.0, 15.0, size=half)      # chi_square_stat
        X[half:, 5] = np.random.normal(24.0, 6.0, size=half)       # noise_variance

    elif feature_dim == 7:
        # Audio/Video: [lsb_ones_ratio, lsb_entropy, audio_lsb_correlation, mean_centroid, std_centroid, mean_rolloff, mfcc_ratio] (Audio)
        # Or Video frame metrics
        # Safe
        X[:half, 0] = np.random.normal(0.5, 0.03, size=half)       # lsb_ones_ratio
        X[:half, 1] = np.random.normal(0.96, 0.03, size=half)      # lsb_entropy
        X[:half, 2] = np.random.normal(0.42, 0.04, size=half)      # audio_lsb_correlation
        X[:half, 3] = np.random.normal(1200.0, 200.0, size=half)   # mean_centroid
        X[:half, 4] = np.random.normal(300.0, 50.0, size=half)     # std_centroid
        X[:half, 5] = np.random.normal(2500.0, 400.0, size=half)   # mean_rolloff
        X[:half, 6] = np.random.normal(0.75, 0.1, size=half)       # mfcc_ratio
        
        # Stego
        X[half:, 0] = np.random.normal(0.5, 0.002, size=half)      # lsb_ones_ratio
        X[half:, 1] = np.random.normal(0.9998, 0.0001, size=half)  # lsb_entropy
        X[half:, 2] = np.random.normal(0.50, 0.005, size=half)     # audio_lsb_correlation
        X[half:, 3] = np.random.normal(1500.0, 250.0, size=half)   # mean_centroid
        X[half:, 4] = np.random.normal(450.0, 75.0, size=half)     # std_centroid
        X[half:, 5] = np.random.normal(3100.0, 500.0, size=half)   # mean_rolloff
        X[half:, 6] = np.random.normal(1.45, 0.15, size=half)      # mfcc_ratio

    return X, y

def main():
    print("=== Training AI Stego Cyber Shield Multi-Classifier ===")
    
    multi_classifier = StegoMultiClassifier()
    feature_shapes = [2, 3, 4, 6, 7]
    
    for shape in feature_shapes:
        print(f"Generating synthetic data and training classifier for feature dimension: {shape}...")
        X, y = generate_synthetic_data(shape, num_samples=2000)
        
        clf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
        clf.fit(X, y)
        
        # Verify training accuracy
        train_acc = clf.score(X, y)
        print(f"Classifier (shape {shape}) trained. Training accuracy: {train_acc * 100:.2f}%")
        
        multi_classifier.add_model(shape, clf)
        
    model_path = os.path.join(os.path.dirname(__file__), "stego_classifier.joblib")
    print(f"Saving combined multi-classifier to: {model_path}...")
    joblib.dump(multi_classifier, model_path)
    print("Model compilation completed successfully.")

if __name__ == "__main__":
    main()
