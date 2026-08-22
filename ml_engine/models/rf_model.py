import os
import joblib
import numpy as np


class RFModel:
    """
    Random Forest inference wrapper.

    Expected artifacts:

        ml_engine/artifacts/rf_model.joblib
        ml_engine/artifacts/scaler.joblib
        ml_engine/artifacts/label_encoder.joblib
    """

    def __init__(self, artifact_dir=None):

        if artifact_dir is None:
            project_root = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..")
            )

            artifact_dir = os.path.join(
                project_root,
                "ml_engine",
                "artifacts"
            )

        self.artifact_dir = artifact_dir

        self.model_path = os.path.join(
            artifact_dir,
            "rf_model.joblib"
        )

        self.scaler_path = os.path.join(
            artifact_dir,
            "scaler.joblib"
        )

        self.encoder_path = os.path.join(
            artifact_dir,
            "label_encoder.joblib"
        )

        self.model = None
        self.scaler = None
        self.label_encoder = None

    def load(self):

        # -----------------------------
        # Check model
        # -----------------------------

        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"RF model not found: {self.model_path}"
            )

        # -----------------------------
        # Load Random Forest
        # -----------------------------

        artifact = joblib.load(self.model_path)

        # Support both:
        #
        # 1. Raw RandomForestClassifier
        #
        # 2. Dictionary containing model
        #

        if isinstance(artifact, dict):

            if "model" in artifact:
                self.model = artifact["model"]

            elif "rf_model" in artifact:
                self.model = artifact["rf_model"]

            elif "classifier" in artifact:
                self.model = artifact["classifier"]

            else:
                raise RuntimeError(
                    "RF artifact is a dictionary but no model was found."
                )

        else:
            self.model = artifact

        # -----------------------------
        # Load scaler
        # -----------------------------

        if os.path.exists(self.scaler_path):

            self.scaler = joblib.load(
                self.scaler_path
            )

        else:

            print(
                "WARNING: scaler.joblib not found. "
                "RF predictions will use raw features."
            )

        # -----------------------------
        # Load label encoder
        # -----------------------------

        if os.path.exists(self.encoder_path):

            self.label_encoder = joblib.load(
                self.encoder_path
            )

        else:

            print(
                "WARNING: label_encoder.joblib not found."
            )

        print("RF model loaded successfully.")

        return True

    def predict(self, features):

        if self.model is None:
            raise RuntimeError(
                "RF model not loaded. Call load() first."
            )

        # Convert input to numpy
        X = np.asarray(
            features,
            dtype=np.float32
        )

        # Make single sample 2D
        if X.ndim == 1:
            X = X.reshape(1, -1)

        # Apply scaler if available
        if self.scaler is not None:
            X_scaled = self.scaler.transform(X)
        else:
            X_scaled = X

        # Prediction
        prediction = self.model.predict(
            X_scaled
        )

        predicted_value = prediction[0]

        # Probability
        probabilities = None

        if hasattr(self.model, "predict_proba"):

            probabilities = self.model.predict_proba(
                X_scaled
            )[0]

        # Decode label
        predicted_label = predicted_value

        if self.label_encoder is not None:

            try:

                predicted_label = self.label_encoder.inverse_transform(
                    [predicted_value]
                )[0]

            except Exception:

                predicted_label = predicted_value

        result = {
            "prediction": str(predicted_label),
            "prediction_id": (
                int(predicted_value)
                if isinstance(
                    predicted_value,
                    (int, np.integer)
                )
                else str(predicted_value)
            )
        }

        if probabilities is not None:

            result["probabilities"] = [
                float(x)
                for x in probabilities
            ]

        return result