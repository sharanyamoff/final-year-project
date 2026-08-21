cat > ml_engine/explainability/shap_engine.py <<'PY'
import numpy as np
import shap


class SHAPEngine:
    """
    SHAP explainability engine for the trained Random Forest.

    Supports the project's saved artifact format:

        {
            "model": RandomForestClassifier(...),
            "label_encoder": LabelEncoder()
        }

    Also supports receiving the RandomForestClassifier directly.

    Handles SHAP outputs from different SHAP versions and converts
    them into one importance value per input feature.
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

    def __init__(self, model, feature_names=None):
        """
        Parameters
        ----------
        model:
            Either:
              1. RandomForestClassifier
              2. Dictionary containing:
                   {
                       "model": RandomForestClassifier,
                       "label_encoder": LabelEncoder
                   }

        feature_names:
            Optional list of feature names.
        """

        # ---------------------------------------------------------
        # IMPORTANT:
        # rf_model.joblib contains a dictionary, not the classifier
        # directly.
        # ---------------------------------------------------------
        if isinstance(model, dict):

            if "model" not in model:
                raise ValueError(
                    "Model dictionary does not contain a 'model' key."
                )

            self.model = model["model"]
            self.label_encoder = model.get("label_encoder")

        else:
            self.model = model
            self.label_encoder = None

        self.feature_names = (
            feature_names
            if feature_names is not None
            else self.DEFAULT_FEATURE_NAMES.copy()
        )

        self.explainer = None

    # =============================================================
    # LOAD
    # =============================================================

    @classmethod
    def load(cls, model_path, feature_names=None):
        """
        Load a saved model artifact.

        Supports both:
          - direct sklearn model
          - dictionary artifact containing "model"
        """

        import joblib

        artifact = joblib.load(model_path)

        return cls(
            artifact,
            feature_names=feature_names
        )

    # =============================================================
    # CREATE SHAP EXPLAINER
    # =============================================================

    def _create_explainer(self):

        if self.explainer is None:

            # Verify that we actually have a sklearn model.
            if isinstance(self.model, dict):

                if "model" not in self.model:
                    raise ValueError(
                        "Invalid model dictionary: missing 'model'."
                    )

                self.model = self.model["model"]

            self.explainer = shap.TreeExplainer(
                self.model
            )

    # =============================================================
    # NORMALIZE SHAP OUTPUT
    # =============================================================

    def _normalize_shap_values(self, shap_values):
        """
        Convert SHAP output from different SHAP versions into:

            samples x features

        For multi-class classification, absolute SHAP impacts
        are averaged across classes.
        """

        # ---------------------------------------------------------
        # CASE 1:
        # Older SHAP versions may return a list:
        #
        # [
        #   class_0 -> samples x features,
        #   class_1 -> samples x features,
        #   ...
        # ]
        # ---------------------------------------------------------

        if isinstance(shap_values, list):

            arrays = []

            for value in shap_values:

                arr = np.asarray(value, dtype=np.float64)

                if arr.ndim == 1:
                    arr = arr.reshape(1, -1)

                elif arr.ndim != 2:
                    raise ValueError(
                        f"Unexpected SHAP class shape: {arr.shape}"
                    )

                arrays.append(arr)

            if not arrays:
                raise ValueError(
                    "SHAP returned an empty list."
                )

            # classes x samples x features
            stacked = np.stack(
                arrays,
                axis=0
            )

            # Average absolute impact across classes.
            normalized = np.mean(
                np.abs(stacked),
                axis=0
            )

            return normalized

        # ---------------------------------------------------------
        # CASE 2:
        # Newer SHAP versions return ndarray.
        # ---------------------------------------------------------

        arr = np.asarray(
            shap_values,
            dtype=np.float64
        )

        # ---------------------------------------------------------
        # (features,)
        # ---------------------------------------------------------

        if arr.ndim == 1:

            return np.abs(
                arr
            ).reshape(1, -1)

        # ---------------------------------------------------------
        # (samples, features)
        # ---------------------------------------------------------

        if arr.ndim == 2:

            return np.abs(arr)

        # ---------------------------------------------------------
        # (samples, features, classes)
        #
        # SHAP 0.52 commonly uses this format for multiclass RF.
        # ---------------------------------------------------------

        if arr.ndim == 3:

            # Normal modern SHAP format:
            #
            # samples x features x classes
            #
            if arr.shape[1] == len(self.feature_names):

                normalized = np.mean(
                    np.abs(arr),
                    axis=2
                )

                return normalized

            # -----------------------------------------------------
            # Alternative:
            #
            # classes x samples x features
            # -----------------------------------------------------

            if arr.shape[2] == len(self.feature_names):

                normalized = np.mean(
                    np.abs(arr),
                    axis=0
                )

                return normalized

            # -----------------------------------------------------
            # Single sample fallback
            # -----------------------------------------------------

            if arr.shape[0] == 1:

                normalized = np.mean(
                    np.abs(arr),
                    axis=-1
                )

                return normalized

            raise ValueError(
                "Unable to determine SHAP multiclass output "
                f"orientation: {arr.shape}"
            )

        raise ValueError(
            f"Unsupported SHAP output shape: {arr.shape}"
        )

    # =============================================================
    # EXPLAIN
    # =============================================================

    def explain(self, X, original_features=None):
        """
        Generate feature-level SHAP explanations.

        Parameters
        ----------
        X:
            Scaled model input.
            Expected shape:
                (1, number_of_features)

        original_features:
            Optional original feature vector.
            Kept for API compatibility.
        """

        self._create_explainer()

        X = np.asarray(
            X,
            dtype=np.float64
        )

        # ---------------------------------------------------------
        # Ensure 2-D input.
        # ---------------------------------------------------------

        if X.ndim == 1:

            X = X.reshape(
                1,
                -1
            )

        if X.ndim != 2:

            raise ValueError(
                "Expected 1-D or 2-D input, "
                f"got shape {X.shape}"
            )

        # ---------------------------------------------------------
        # Verify feature count.
        # ---------------------------------------------------------

        if X.shape[1] != len(self.feature_names):

            raise ValueError(
                "Feature count mismatch: "
                f"model input has {X.shape[1]} features, "
                f"but SHAPEngine expects "
                f"{len(self.feature_names)} features."
            )

        # ---------------------------------------------------------
        # Calculate SHAP values.
        # ---------------------------------------------------------

        shap_result = self.explainer.shap_values(
            X
        )

        # ---------------------------------------------------------
        # Normalize SHAP output.
        # ---------------------------------------------------------

        normalized = self._normalize_shap_values(
            shap_result
        )

        normalized = np.asarray(
            normalized,
            dtype=np.float64
        )

        # ---------------------------------------------------------
        # We normally explain one current flow.
        # Use first row if multiple rows are supplied.
        # ---------------------------------------------------------

        if normalized.ndim == 1:

            mean_abs_impact = normalized

        else:

            mean_abs_impact = normalized[0]

        mean_abs_impact = np.asarray(
            mean_abs_impact,
            dtype=np.float64
        ).reshape(-1)

        # ---------------------------------------------------------
        # Protect against SHAP returning unexpected feature count.
        # ---------------------------------------------------------

        feature_count = min(
            len(self.feature_names),
            len(mean_abs_impact)
        )

        explanations = []

        for i in range(feature_count):

            value = float(
                mean_abs_impact[i]
            )

            explanations.append(
                {
                    "feature": self.feature_names[i],
                    "shap_value": value,
                    "importance": value
                }
            )

        # ---------------------------------------------------------
        # Highest-impact features first.
        # ---------------------------------------------------------

        explanations.sort(
            key=lambda x: x["shap_value"],
            reverse=True
        )

        return {
            "features": explanations,
            "top_features": explanations[:5]
        }
PY