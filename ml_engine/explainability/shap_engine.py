import numpy as np
import shap


class SHAPEngine:
    """
    SHAP explainability engine for the trained Random Forest.

    Supports SHAP outputs returned as:
      - list of arrays
      - 2-D numpy arrays
      - 3-D numpy arrays

    The final explanation contains one importance value
    for each input feature.
    """

    def __init__(self, model=None, feature_names=None):
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

        # Create the explainer immediately if a model was supplied.
        if self.model is not None:
            self._create_explainer()

    # =========================================================
    # LOAD MODEL
    # =========================================================

    def load(self, model):
        """
        Load or replace the trained model.

        This method is required by ml_engine/api/main.py.
        """

        self.model = model
        self.explainer = None

        self._create_explainer()

    # =========================================================
    # CREATE SHAP EXPLAINER
    # =========================================================

    def _create_explainer(self):
        """
        Create the SHAP TreeExplainer.
        """

        if self.model is None:
            raise ValueError(
                "Cannot create SHAP explainer: model is None."
            )

        if self.explainer is None:
            self.explainer = shap.TreeExplainer(
                self.model
            )

    # =========================================================
    # NORMALIZE SHAP OUTPUT
    # =========================================================

    def _normalize_shap_values(self, shap_values):
        """
        Convert SHAP output from different SHAP versions
        into:

            samples x features

        For multi-class classification, absolute SHAP
        contributions are averaged across classes.
        """

        # -----------------------------------------------------
        # CASE 1:
        # SHAP returns a list
        #
        # Example:
        #
        # [
        #     class_0 -> (samples, features),
        #     class_1 -> (samples, features),
        #     ...
        # ]
        # -----------------------------------------------------

        if isinstance(shap_values, list):

            arrays = []

            for value in shap_values:

                arr = np.asarray(value)

                if arr.ndim == 1:
                    arr = arr.reshape(1, -1)

                elif arr.ndim > 2:
                    arr = arr.reshape(
                        arr.shape[0],
                        -1
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

            # Average absolute SHAP impact
            # across classes.
            normalized = np.mean(
                np.abs(stacked),
                axis=0
            )

            return normalized

        # -----------------------------------------------------
        # CASE 2:
        # SHAP returns numpy ndarray
        # -----------------------------------------------------

        arr = np.asarray(shap_values)

        # -----------------------------------------------------
        # 1-D
        #
        # features
        # -----------------------------------------------------

        if arr.ndim == 1:

            return np.abs(
                arr
            ).reshape(1, -1)

        # -----------------------------------------------------
        # 2-D
        #
        # samples x features
        # -----------------------------------------------------

        if arr.ndim == 2:

            return np.abs(arr)

        # -----------------------------------------------------
        # 3-D
        #
        # Multi-class SHAP output.
        # -----------------------------------------------------

        if arr.ndim == 3:

            # ---------------------------------------------
            # samples x features x classes
            # ---------------------------------------------

            if (
                arr.shape[0] >= 1
                and arr.shape[1] == len(self.feature_names)
            ):

                normalized = np.mean(
                    np.abs(arr),
                    axis=-1
                )

                return normalized

            # ---------------------------------------------
            # classes x samples x features
            # ---------------------------------------------

            if arr.shape[-1] == len(
                self.feature_names
            ):

                normalized = np.mean(
                    np.abs(arr),
                    axis=0
                )

                return normalized

            # ---------------------------------------------
            # One sample:
            #
            # 1 x features x classes
            # ---------------------------------------------

            if arr.shape[0] == 1:

                normalized = np.mean(
                    np.abs(arr),
                    axis=-1
                )

                return normalized

            # ---------------------------------------------
            # Safe fallback
            # ---------------------------------------------

            normalized = np.mean(
                np.abs(arr),
                axis=-1
            )

            return normalized

        # -----------------------------------------------------
        # Unsupported SHAP output
        # -----------------------------------------------------

        raise ValueError(
            "Unsupported SHAP output shape: "
            f"{arr.shape}"
        )

    # =========================================================
    # EXPLAIN
    # =========================================================

    def explain(
        self,
        X,
        original_features=None
    ):
        """
        Generate SHAP feature explanations.

        Parameters
        ----------
        X:
            Scaled model input.

        original_features:
            Optional original feature vector.
            Kept for API compatibility.

        Returns
        -------
        dict
            Feature explanations and top features.
        """

        # Make sure the SHAP explainer exists.
        self._create_explainer()

        # Convert input to numpy.
        X = np.asarray(
            X,
            dtype=np.float64
        )

        # -----------------------------------------------------
        # Ensure 2-D input
        # -----------------------------------------------------

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

        # -----------------------------------------------------
        # Validate feature count
        # -----------------------------------------------------

        if X.shape[1] != len(
            self.feature_names
        ):

            raise ValueError(
                "Feature count mismatch. "
                f"Model input contains {X.shape[1]} "
                f"features, but SHAP expects "
                f"{len(self.feature_names)}."
            )

        # -----------------------------------------------------
        # Calculate SHAP values
        # -----------------------------------------------------

        shap_result = self.explainer.shap_values(
            X
        )

        # -----------------------------------------------------
        # Normalize SHAP output
        # -----------------------------------------------------

        normalized = self._normalize_shap_values(
            shap_result
        )

        normalized = np.asarray(
            normalized
        )

        # -----------------------------------------------------
        # Make sure normalized result is 2-D
        # -----------------------------------------------------

        if normalized.ndim == 1:

            normalized = normalized.reshape(
                1,
                -1
            )

        if normalized.ndim != 2:

            raise ValueError(
                "Normalized SHAP output has "
                f"unexpected shape {normalized.shape}"
            )

        # -----------------------------------------------------
        # We explain the first/current flow.
        # -----------------------------------------------------

        mean_abs_impact = np.asarray(
            normalized[0]
        ).reshape(-1)

        # -----------------------------------------------------
        # Verify feature count
        # -----------------------------------------------------

        if len(mean_abs_impact) != len(
            self.feature_names
        ):

            raise ValueError(
                "SHAP feature count mismatch. "
                f"SHAP returned "
                f"{len(mean_abs_impact)} values, "
                f"but expected "
                f"{len(self.feature_names)}."
            )

        # -----------------------------------------------------
        # Build explanations
        # -----------------------------------------------------

        explanations = []

        for i, feature_name in enumerate(
            self.feature_names
        ):

            value = float(
                mean_abs_impact[i]
            )

            explanations.append(
                {
                    "feature": feature_name,
                    "shap_value": value,
                    "importance": value,
                }
            )

        # -----------------------------------------------------
        # Highest impact first
        # -----------------------------------------------------

        explanations.sort(
            key=lambda item: item["shap_value"],
            reverse=True
        )

        # -----------------------------------------------------
        # Return result
        # -----------------------------------------------------

        return {
            "features": explanations,
            "top_features": explanations[:5],
        }