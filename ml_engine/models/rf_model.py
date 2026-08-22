import os
import joblib


class RFModel:
    def __init__(self, artifact_dir):
        self.artifact_dir = artifact_dir
        self.model_path = os.path.join(artifact_dir, "rf_model.joblib")
        self.model = None
        self.label_encoder = None

    def load(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"RF model not found: {self.model_path}"
            )

        artifacts = joblib.load(self.model_path)

        if isinstance(artifacts, dict):
            self.model = artifacts.get("model")
            self.label_encoder = artifacts.get("label_encoder")
        else:
            self.model = artifacts

        if self.model is None:
            raise RuntimeError("RF model could not be loaded")

        label_path = os.path.join(
            self.artifact_dir,
            "label_encoder.joblib"
        )

        if os.path.exists(label_path):
            self.label_encoder = joblib.load(label_path)

        return True

    def predict(self, features):
        if self.model is None:
            raise RuntimeError("RF model not loaded")

        prediction = self.model.predict(features)[0]

        probabilities = self.model.predict_proba(features)[0]

        if self.label_encoder is not None:
            try:
                predicted_class = self.label_encoder.inverse_transform(
                    [prediction]
                )[0]
            except Exception:
                predicted_class = str(prediction)
        else:
            predicted_class = str(prediction)

        return {
            "prediction": predicted_class,
            "confidence": float(max(probabilities))
        }
PY