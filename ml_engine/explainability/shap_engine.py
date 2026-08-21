import numpy as np
import shap


class SHAPEngine:
    """
    SHAP explainability engine for the trained Random Forest.

    Handles both:
      - SHAP versions returning a list of arrays
      - SHAP versions returning a 3-D ndarray

    The final explanation is converted into one importance value
    per input feature.
    """

    def __init__(self, model, feature_names=None):
        self.model = model

        self.feature_names = feature_names or [
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

        self.explainer = None

    def _create_explainer(self):
        if self.explainer is None:
            self.explainer = shap.TreeExplainer(self.model)

    def _normalize_shap_values(self, shap_values):
        """
        Convert SHAP output from different SHAP versions into
        a 2-D array:

            samples x features

        For multi-class classification, the absolute SHAP
        impacts are averaged across classes.
        """

        # ---------------------------------------------------------
        # Case 1: SHAP returns a list
        #
        # Older SHAP versions commonly return:
        #
        # [
        #   class_0 -> (samples, features),
        #   class_1 -> (samples, features),
        #   ...
        # ]
        # ---------------------------------------------------------
        if isinstance(shap_values, list):

            arrays = []

            for value in shap_values:
                arr = np.asarray(value)

                if arr.ndim == 1:
                    arr = arr.reshape(1, -1)

                elif arr.ndim > 2:
                    arr = arr.reshape(arr.shape[0], -1)

                arrays.append(arr)

            if not arrays:
                raise ValueError("SHAP returned an empty list")

            # Stack classes:
            # classes x samples x features
            stacked = np.stack(arrays, axis=0)

            # Average absolute contribution across classes
            normalized = np.mean(np.abs(stacked), axis=0)

            return normalized

        # ---------------------------------------------------------
        # Case 2: SHAP returns an ndarray
        # ---------------------------------------------------------
        arr = np.asarray(shap_values)

        # Single sample, single output:
        # (features,)
        if arr.ndim == 1:
            return np.abs(arr).reshape(1, -1)

        # Normal binary/single-output:
        # (samples, features)
        if arr.ndim == 2:
            return np.abs(arr)

        # Multi-class:
        #
        # Depending on SHAP version this can be:
        #
        # (samples, features, classes)
        #
        # or another equivalent orientation.
        #
        if arr.ndim == 3:

            # Most recent SHAP format:
            # samples x features x classes
            if arr.shape[0] == 1:
                normalized = np.mean(
                    np.abs(arr),
                    axis=-1
                )

                return normalized

            # If features are the last dimension:
            if arr.shape[1] == len(self.feature_names):
                normalized = np.mean(
                    np.abs(arr),
                    axis=-1
                )

                return normalized

            # Older possible format:
            # classes x samples x features
            if arr.shape[-1] == len(self.feature_names):
                normalized = np.mean(
                    np.abs(arr),
                    axis=0
                )

                return normalized

            # Safe fallback
            normalized = np.mean(
                np.abs(arr),
                axis=-1
            )

            return normalized

        # ---------------------------------------------------------
        # Unexpected SHAP shape
        # ---------------------------------------------------------
        raise ValueError(
            f"Unsupported SHAP output shape: {arr.shape}"
        )

    def explain(self, X, original_features=None):
        """
        Generate feature-level SHAP explanations.

        Parameters
        ----------
        X:
            Scaled model input. Shape should normally be
            (1, number_of_features).

        original_features:
            Optional original feature vector. Kept for API
            compatibility.

        Returns
        -------
        dict
            Explanation containing feature importance values.
        """

        self._create_explainer()

        X = np.asarray(X, dtype=np.float64)

        # Ensure 2-D input
        if X.ndim == 1:
            X = X.reshape(1, -1)

        if X.ndim != 2:
            raise ValueError(
                f"Expected 1-D or 2-D input, got shape {X.shape}"
            )

        # ---------------------------------------------------------
        # Calculate SHAP values
        # ---------------------------------------------------------
        shap_result = self.explainer.shap_values(X)

        # ---------------------------------------------------------
        # Normalize all SHAP output formats
        # ---------------------------------------------------------
        normalized = self._normalize_shap_values(shap_result)

        # We are explaining one current flow.
        #
        # If multiple rows are supplied, use the first row.
        mean_abs_impact = np.asarray(normalized[0]).reshape(-1)

        # ---------------------------------------------------------
        # Make sure feature count matches
        # ---------------------------------------------------------
        feature_count = min(
            len(self.feature_names),
            len(mean_abs_impact)
        )

        explanations = []

        for i in range(feature_count):

            value = float(mean_abs_impact[i])

            explanations.append({
                "feature": self.feature_names[i],
                "shap_value": value,
                "importance": value
            })

        # Highest impact first
        explanations.sort(
            key=lambda x: x["shap_value"],
            reverse=True
        )

        return {
            "features": explanations,
            "top_features": explanations[:5]
        }