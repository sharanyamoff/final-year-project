import joblib
import os

class RFModel:
    def __init__(self, artifact_dir):
        self.model_path = os.path.join(artifact_dir, 'rf_model.joblib')
        self.model = None
        self.label_encoder = None
        
    def load(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError("RF model artifact missing")
        artifacts = joblib.load(self.model_path)
        self.model = artifacts['model']
        self.label_encoder = artifacts['label_encoder']
        return True
        
    def predict(self, features_scaled):
        if not self.model:
            raise RuntimeError("Model not loaded")
        probs = self.model.predict_proba(features_scaled)[0]
        pred_idx = self.model.predict(features_scaled)[0]
        pred_class = self.label_encoder.classes_[pred_idx]
        
        prob_dict = {str(c): float(p) for c, p in zip(self.label_encoder.classes_, probs)}
        return pred_class, prob_dict, probs
