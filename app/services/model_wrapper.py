import numpy as np

class StegoMultiClassifier:
    """
    A custom wrapper classifier that manages separate sub-classifiers for 
    different feature-vector dimensions (representing different file formats).
    """
    def __init__(self):
        self.models = {}

    def add_model(self, feature_dim: int, model):
        self.models[feature_dim] = model

    def predict_proba(self, X):
        X = np.asarray(X)
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
            
        feature_dim = X.shape[1]
        if feature_dim in self.models:
            return self.models[feature_dim].predict_proba(X)
        else:
            # Raise ValueError if shape is not supported, forcing AIEngine to fall back to pure DSP
            raise ValueError(f"No classifier model trained for feature dimension {feature_dim}")
