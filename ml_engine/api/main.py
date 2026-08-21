import os
import numpy as np
import joblib

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict

from ml_engine.models.dqn_model import DQNAgent
from ml_engine.explainability.shap_engine import SHAPEngine


app = FastAPI(title="XRL-IDARS ML Engine")


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
ARTIFACT_DIR = os.path.join(BASE_DIR, "artifacts")


# ============================================================
# FEATURE SCHEMA
# MUST MATCH TRAINING ORDER
# ============================================================

FEATURE_SCHEMA = [
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


# ============================================================
# GLOBALS
# ============================================================

rf_model = None
label_encoder = None
lstm_model = None
dqn = None
shap_engine = None
scaler = None

models_loaded = False


# ============================================================
# REQUEST MODEL
# ============================================================

class PredictRequest(BaseModel):
    flow_id: str
    features: Dict[str, float]
    sequence: List[Dict[str, float]]
    env_state: Dict[str, float]


# ============================================================
# LOAD RANDOM FOREST
# ============================================================

def load_rf():

    global rf_model
    global label_encoder

    path = os.path.join(
        ARTIFACT_DIR,
        "rf_model.joblib"
    )

    artifact = joblib.load(path)

    print("RF artifact type:", type(artifact))

    # Your artifact is:
    #
    # {
    #     "model": RandomForestClassifier(...),
    #     "label_encoder": LabelEncoder(...)
    # }

    if isinstance(artifact, dict):

        if "model" not in artifact:
            raise ValueError(
                "rf_model.joblib does not contain 'model'"
            )

        rf_model = artifact["model"]
        label_encoder = artifact.get("label_encoder")

    else:

        rf_model = artifact
        label_encoder = None

    print("RF model type:", type(rf_model))

    return rf_model


# ============================================================
# LOAD LSTM
# ============================================================

def load_lstm():

    global lstm_model

    path = os.path.join(
        ARTIFACT_DIR,
        "lstm_model.joblib"
    )

    if not os.path.exists(path):

        print("WARNING: LSTM model not found.")
        lstm_model = None
        return None

    try:

        lstm_model = joblib.load(path)

        print(
            "LSTM model loaded:",
            type(lstm_model)
        )

        return lstm_model

    except Exception as e:

        print(
            "WARNING: Could not load LSTM:",
            e
        )

        lstm_model = None

        return None


# ============================================================
# LOAD DQN
# ============================================================

def load_dqn():

    global dqn

    try:

        dqn = DQNAgent(ARTIFACT_DIR)

        dqn.load()

        print("DQN loaded successfully.")

        return dqn

    except Exception as e:

        print(
            "WARNING: DQN could not be loaded:",
            e
        )

        dqn = None

        return None


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def load_models():

    global models_loaded
    global scaler
    global shap_engine

    models_loaded = False

    try:

        print("=" * 60)
        print("XRL-IDARS ML ENGINE STARTUP")
        print("=" * 60)

        # ----------------------------------------------------
        # SCALER
        # ----------------------------------------------------

        scaler_path = os.path.join(
            ARTIFACT_DIR,
            "scaler.joblib"
        )

        if not os.path.exists(scaler_path):

            print(
                "ERROR: scaler.joblib not found."
            )

            return

        scaler = joblib.load(scaler_path)

        print(
            "Scaler loaded:",
            type(scaler)
        )

        # ----------------------------------------------------
        # RANDOM FOREST
        # ----------------------------------------------------

        load_rf()

        # ----------------------------------------------------
        # SHAP
        # ----------------------------------------------------

        shap_engine = SHAPEngine(
            rf_model,
            FEATURE_SCHEMA
        )

        print("SHAP engine loaded successfully.")

        # ----------------------------------------------------
        # LSTM
        # ----------------------------------------------------

        load_lstm()

        # ----------------------------------------------------
        # DQN
        # ----------------------------------------------------

        load_dqn()

        # ----------------------------------------------------
        # EVERYTHING REQUIRED FOR RF INFERENCE EXISTS
        # ----------------------------------------------------

        models_loaded = True

        print("=" * 60)
        print("ALL REQUIRED MODELS LOADED SUCCESSFULLY")
        print("=" * 60)

    except Exception as e:

        models_loaded = False

        print("=" * 60)
        print("FAILED TO LOAD MODELS")
        print("ERROR:", repr(e))
        print("=" * 60)


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "ok",
        "models_loaded": models_loaded
    }


# ============================================================
# MODEL INFO
# ============================================================

@app.get("/model-info")
def model_info():

    if not models_loaded:

        return {
            "status": "MODEL_NOT_LOADED"
        }

    meta_path = os.path.join(
        ARTIFACT_DIR,
        "metadata.joblib"
    )

    metadata = "unknown"

    if os.path.exists(meta_path):

        try:

            metadata = joblib.load(
                meta_path
            )

        except Exception as e:

            metadata = str(e)

    return {
        "status": "MODEL_LOADED",
        "metadata": metadata
    }


# ============================================================
# PREDICT
# ============================================================

@app.post("/predict")
def predict(req: PredictRequest):

    # --------------------------------------------------------
    # CHECK MODELS
    # --------------------------------------------------------

    if not models_loaded:

        raise HTTPException(
            status_code=503,
            detail="MODEL_NOT_TRAINED or MODEL_INFERENCE_ERROR"
        )

    # --------------------------------------------------------
    # CHECK FEATURES
    # --------------------------------------------------------

    for feature in FEATURE_SCHEMA:

        if feature not in req.features:

            raise HTTPException(
                status_code=400,
                detail=f"Missing feature: {feature}"
            )

    # --------------------------------------------------------
    # CURRENT FEATURE VECTOR
    # --------------------------------------------------------

    try:

        curr_vec = np.array(
            [[
                req.features[feature]
                for feature in FEATURE_SCHEMA
            ]],
            dtype=np.float64
        )

        curr_scaled = scaler.transform(
            curr_vec
        )

    except Exception as e:

        raise HTTPException(
            status_code=400,
            detail=f"Feature preprocessing failed: {str(e)}"
        )

    # ========================================================
    # RANDOM FOREST
    # ========================================================

    try:

        rf_raw_probs = rf_model.predict_proba(
            curr_scaled
        )[0]

        rf_prediction = rf_model.predict(
            curr_scaled
        )[0]

        # Convert numeric/class prediction to
        # original label if LabelEncoder exists.

        if label_encoder is not None:

            try:

                rf_class = label_encoder.inverse_transform(
                    [int(rf_prediction)]
                )[0]

            except Exception:

                rf_class = str(rf_prediction)

        else:

            rf_class = str(rf_prediction)

        rf_class = str(rf_class)

        max_rf_prob = float(
            np.max(rf_raw_probs)
        )

        # Build probability dictionary

        if label_encoder is not None:

            try:

                labels = label_encoder.inverse_transform(
                    np.arange(
                        len(rf_raw_probs)
                    )
                )

                rf_probs = {
                    str(label): float(prob)
                    for label, prob
                    in zip(labels, rf_raw_probs)
                }

            except Exception:

                rf_probs = {
                    str(i): float(prob)
                    for i, prob
                    in enumerate(rf_raw_probs)
                }

        else:

            rf_probs = {
                str(i): float(prob)
                for i, prob
                in enumerate(rf_raw_probs)
            }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Random Forest inference failed: {str(e)}"
        )

    # ========================================================
    # SHAP
    # ========================================================

    try:

        shap_out = shap_engine.explain(
            curr_scaled,
            curr_vec[0]
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"SHAP inference failed: {str(e)}"
        )

    # ========================================================
    # LSTM
    # ========================================================

    lstm_score = 0.0
    lstm_status = "PENDING"

    if len(req.sequence) == 5:

        if lstm_model is None:

            lstm_status = "NOT_LOADED"

        else:

            try:

                seq_vec = []

                for sample in req.sequence:

                    for feature in FEATURE_SCHEMA:

                        if feature not in sample:

                            raise HTTPException(
                                status_code=400,
                                detail=(
                                    "Missing feature in sequence: "
                                    f"{feature}"
                                )
                            )

                    seq_vec.append(
                        [
                            sample[feature]
                            for feature in FEATURE_SCHEMA
                        ]
                    )

                seq_array = np.array(
                    seq_vec,
                    dtype=np.float64
                )

                seq_scaled = scaler.transform(
                    seq_array
                )

                # ------------------------------------------------
                # Support common LSTM wrapper formats
                # ------------------------------------------------

                if hasattr(
                    lstm_model,
                    "predict"
                ):

                    prediction = lstm_model.predict(
                        np.expand_dims(
                            seq_scaled,
                            axis=0
                        )
                    )

                    lstm_score = float(
                        np.asarray(prediction).reshape(-1)[0]
                    )

                else:

                    lstm_status = "UNSUPPORTED_MODEL"

                if lstm_status != "UNSUPPORTED_MODEL":

                    lstm_status = "EVALUATED"

            except HTTPException:

                raise

            except Exception as e:

                print(
                    "LSTM inference warning:",
                    repr(e)
                )

                lstm_score = 0.0
                lstm_status = "ERROR"

    elif len(req.sequence) > 5:

        raise HTTPException(
            status_code=400,
            detail="Sequence length exceeds 5"
        )

    # ========================================================
    # RISK SCORE
    # ========================================================

    if lstm_status == "EVALUATED":

        risk_score = (
            0.6 * max_rf_prob
            +
            0.4 * lstm_score
        )

    else:

        risk_score = max_rf_prob

    risk_score = float(
        np.clip(
            risk_score,
            0.0,
            1.0
        )
    )

    # ========================================================
    # DQN
    # ========================================================

    dqn_action = "NO_ACTION"
    dqn_q_vals = []

    if dqn is not None:

        try:

            dqn_state = [

                max_rf_prob,

                lstm_score,

                risk_score,

                req.features.get(
                    "flow_packets_per_s",
                    0.0
                ),

                req.features.get(
                    "syn_count",
                    0.0
                ),

                req.env_state.get(
                    "historical_incident_count",
                    0.0
                ),

                req.env_state.get(
                    "is_blocked",
                    0.0
                )
            ]

            dqn_action, dqn_q_vals = dqn.get_action(
                dqn_state
            )

        except Exception as e:

            print(
                "DQN inference warning:",
                repr(e)
            )

            dqn_action = "NO_ACTION"
            dqn_q_vals = []

    # ========================================================
    # RESPONSE
    # ========================================================

    return {

        "flow_id": req.flow_id,

        "rf": {
            "predicted_class": rf_class,
            "probabilities": rf_probs
        },

        "lstm": {
            "status": lstm_status,
            "anomaly_score": float(lstm_score)
        },

        "risk_score": risk_score,

        "shap": shap_out,

        "dqn": {
            "action": dqn_action,
            "q_values": dqn_q_vals
        }
    }