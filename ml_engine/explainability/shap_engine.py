import shap
import os
import joblib
import numpy as np

class SHAPEngine:
    def __init__(self, artifact_dir):
        self.explainer = None
        self.feature_names = None
        
    def load(self, rf_model, feature_names):
        bg_path = os.path.join(os.path.dirname(rf_model.model_path), 'shap_background.joblib')
        if not os.path.exists(bg_path):
            raise FileNotFoundError("SHAP background data missing")
        background = joblib.load(bg_path)
        self.explainer = shap.TreeExplainer(rf_model.model, background)
        self.feature_names = feature_names
        return True
        
    def explain(self, features_scaled, original_features):
        if self.explainer is None:
            raise RuntimeError("SHAP explainer not loaded")
            
        shap_values = self.explainer.shap_values(features_scaled)
        
        if isinstance(shap_values, list):
            # Multiclass: take mean of absolute impacts across classes
            mean_abs_impact = np.mean([np.abs(sv[0]) for sv in shap_values], axis=0)
        else:
            # Binary or single explanation
            mean_abs_impact = np.abs(shap_values[0])
            
        explanations = []
        for i, fname in enumerate(self.feature_names):
            explanations.append({
                "feature": fname,
                "shap_value": float(mean_abs_impact[i]),
                "actual_value": float(original_features[i])
            })
            
        explanations.sort(key=lambda x: x["shap_value"], reverse=True)
        return explanations
