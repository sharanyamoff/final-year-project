import os
import numpy as np
import shap


class SHAPEngine:
    """
    SHAP explainability engine for the Random Forest model.

    Compatible with the FastAPI main.py flow:

        shap_engine = SHAPEngine(ARTIFACT_DIR)
        shap_engine.load(rf, FEATURE_SCHEMA)
        shap_engine.explain(X, original_features)
    """

    DEFAULT_FEATURE_NAMES = [
        "flow_duration_ms",
        "flow_packets_per_s",
        "flow_bytes_per_s",
        "packet_length_mean",
        "packet_length_std",
        "syn_count",
        "ack_count",
        "rst_count",
        "fin_count",
        "syn_ack_ratio",
    ]

    def __init__(self, artifact_dir=None):
        self.artifact_dir = artifact_dir
        self.model = None
        self.label_encoder = None
        self.feature_names = self.DEFAULT_FEATURE_NAMES.copy()
        self.explainer = None

    def load(self, rf_model, feature_names=None):
        """
        Load the Random Forest model from the RFModel wrapper.

        Supports:
        - RFModel wrapper with .model
        - RFModel wrapper with .rf
        - direct sklearn model
        - dictionary containing 'model'
        """

        model = rf_model

        # RFModel wrapper commonly stores sklearn model in .model
        if hasattr(rf_model, "model"):
            model = rf_model.model

        # Alternative wrapper attribute
        elif hasattr(rf_model, "rf"):
            model = rf_model.rf

        # Dictionary artifact
        if isinstance(model, dict):
            if "model" not in model:
                raise ValueError(
                    "Random Forest model dictionary does not contain 'model'."
                )

            self.model = model["model"]
            self.label_encoder = model.get("label_encoder")

        else:
            self.model = model

            if hasattr(rf_model, "label_encoder"):
                self.label_encoder = rf_model.label_encoder

        if self.model is None:
            raise ValueError("Random Forest model could not be loaded.")

        if feature_names is not None:
            self.feature_names = list(feature_names)

        self.explainer = shap.TreeExplainer(self.model)

        return self

    def _normalize_shap_values(self, shap_values):
        """
        Convert SHAP output from different SHAP versions into:

            samples x features

        For multiclass classification, average absolute
        SHAP impact across classes.
        """

        # Older SHAP versions:
        # list[class] -> samples x features
        if isinstance(shap_values, list):

            arrays = []

            for value in shap_values:

                arr = np.asarray(value, dtype=np.float64)

                if arr.ndim == 1:
                    arr = arr.reshape(1, -1)

                if arr.ndim != 2:
                    raise ValueError(
                        f"Unexpected SHAP class shape: {arr.shape}"
                    )

                arrays.append(arr)

            if not arrays:
                raise ValueError("SHAP returned an empty list.")

            stacked = np.stack(arrays, axis=0)

            return np.mean(np.abs(stacked), axis=0)

        arr = np.asarray(shap_values, dtype=np.float64)

        # One-dimensional output
        if arr.ndim == 1:
            return np.abs(arr).reshape(1, -1)

        # samples x features
        if arr.ndim == 2:
            return np.abs(arr)

        # Multiclass output
        if arr.ndim == 3:

            # samples x features x classes
            if arr.shape[1] == len(self.feature_names):
                return np.mean(np.abs(arr), axis=2)

            # classes x samples x features
            if arr.shape[2] == len(self.feature_names):
                return np.mean(np.abs(arr), axis=0)

            # Single-sample fallback
            if arr.shape[0] == 1:
                return np.mean(np.abs(arr), axis=-1)

            raise ValueError(
                "Unable to determine SHAP output orientation: "
                f"{arr.shape}"
            )

        raise ValueError(
            f"Unsupported SHAP output shape: {arr.shape}"
        )

    def explain(self, X, original_features=None):
        """
        Generate feature-level SHAP explanations.

        Parameters
        ----------
        X:
            Model input, normally scaled input with shape
            (1, number_of_features).

        original_features:
            Original unscaled features.
            Kept for API compatibility.
        """

        if self.model is None:
            raise RuntimeError(
                "SHAPEngine has not been loaded. "
                "Call shap_engine.load(...) first."
            )

        if self.explainer is None:
            self.explainer = shap.TreeExplainer(self.model)

        X = np.asarray(X, dtype=np.float64)

        if X.ndim == 1:
            X = X.reshape(1, -1)

        if X.ndim != 2:
            raise ValueError(
                f"Expected 1-D or 2-D input, got shape {X.shape}"
            )

        if X.shape[1] != len(self.feature_names):
            raise ValueError(
                f"Feature count mismatch: input has {X.shape[1]} "
                f"features, but SHAPEngine expects "
                f"{len(self.feature_names)}."
            )

        # Calculate SHAP values
        shap_result = self.explainer.shap_values(X)

        # Normalize across SHAP versions
        normalized = self._normalize_shap_values(shap_result)

        normalized = np.asarray(
            normalized,
            dtype=np.float64
        )

        if normalized.ndim == 1:
            impacts = normalized
        else:
            impacts = normalized[0]

        impacts = np.asarray(
            impacts,
            dtype=np.float64
        ).reshape(-1)

        feature_count = min(
            len(self.feature_names),
            len(impacts)
        )

        explanations = []

        for i in range(feature_count):

            value = float(impacts[i])

            explanations.append(
                {
                    "feature": self.feature_names[i],
                    "shap_value": value,
                    "importance": value,
                }
            )

        # Highest-impact features first
        explanations.sort(
            key=lambda x: x["shap_value"],
            reverse=True
        )

        return {
            "features": explanations,
            "top_features": explanations[:5],
        }