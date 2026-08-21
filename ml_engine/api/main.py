import sys
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Dict, List

import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

ML_ENGINE_DIR = PROJECT_ROOT / "ml_engine"
ARTIFACT_DIR = ML_ENGINE_DIR / "artifacts"

print("=" * 60)
print("XRL-IDARS ML ENGINE STARTUP")
print("=" * 60)
print("PROJECT_ROOT:", PROJECT_ROOT)
print("ARTIFACT_DIR:", ARTIFACT_DIR)


# ============================================================
# IMPORTS
# ============================================================

from ml_engine.models.rf_model import RFModel
from ml_engine.models.dqn_model import DQNAgent
from ml_engine.explainability.shap_engine import SHAPEngine


# ============================================================
# FEATURE SCHEMA
# ============================================================

FEATURE_NAMES = [
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
# GLOBAL MODELS
# ============================================================

rf_model = None
dqn_agent = None
shap_engine = None
lstm_model = None
scaler = None

models_loaded = False


# ============================================================
# REQUEST
# ============================================================

class PredictRequest(BaseModel):

    flow_id: str = "unknown"

    features: Dict[str, float]

    sequence: List[Dict[str, float]] = []

    env_state: Dict[str, float] = {}


# ============================================================
# LOAD MODELS
# ============================================================

def load_models():

    global rf_model
    global dqn_agent
    global shap_engine
    global lstm_model
    global scaler
    global models_loaded

    print()
    print("=" * 60)
    print("LOADING MODELS")
    print("=" * 60)

    # --------------------------------------------------------
    # Check artifact directory
    # --------------------------------------------------------

    if not ARTIFACT_DIR.exists():

        print(
            "ARTIFACT DIRECTORY DOES NOT EXIST:"
        )

        print(ARTIFACT_DIR)

        models_loaded = False

        return


    # --------------------------------------------------------
    # Show artifacts
    # --------------------------------------------------------

    print("Available artifacts:")

    for file in sorted(ARTIFACT_DIR.iterdir()):

        if file.is_file():

            print(
                "  -",
                file.name
            )


    # ========================================================
    # RANDOM FOREST
    # ========================================================

    try:

        rf_model = RFModel(
            str(ARTIFACT_DIR)
        )

        rf_model.load()

        print(
            "RF model loaded successfully."
        )

    except Exception as e:

        print(
            "RF MODEL LOADING FAILED:",
            repr(e)
        )

        rf_model = None


    # ========================================================
    # SCALER
    # ========================================================

    try:

        import joblib

        scaler_path = (
            ARTIFACT_DIR /
            "scaler.joblib"
        )

        if scaler_path.exists():

            scaler = joblib.load(
                scaler_path
            )

            print(
                "Scaler loaded:",
                type(scaler)
            )

        else:

            print(
                "WARNING: scaler.joblib missing"
            )

            scaler = None

    except Exception as e:

        print(
            "SCALER LOADING FAILED:",
            repr(e)
        )

        scaler = None


    # ========================================================
    # DQN
    # ========================================================

    try:

        dqn_agent = DQNAgent(
            str(ARTIFACT_DIR)
        )

        dqn_agent.load()

        print(
            "DQN loaded successfully."
        )

    except Exception as e:

        print(
            "DQN LOADING FAILED:",
            repr(e)
        )

        dqn_agent = None


    # ========================================================
    # LSTM
    # ========================================================

    try:

        from tensorflow.keras.models import load_model

        candidates = [

            ML_ENGINE_DIR /
            "lstm_intrusion_model.keras",

            ARTIFACT_DIR /
            "lstm_model.keras",

            ML_ENGINE_DIR /
            "models" /
            "intrusion_lstm.keras",

            ML_ENGINE_DIR /
            "models" /
            "lstm_intrusion_detector.keras",

        ]

        for path in candidates:

            if path.exists():

                lstm_model = load_model(
                    str(path)
                )

                print(
                    "LSTM model loaded:",
                    path
                )

                break

        if lstm_model is None:

            print(
                "WARNING: LSTM model not found"
            )

    except Exception as e:

        print(
            "LSTM LOADING FAILED:",
            repr(e)
        )

        lstm_model = None


    # ========================================================
    # SHAP
    # ========================================================

    try:

        if rf_model is None:

            raise RuntimeError(
                "RF model must be loaded before SHAP"
            )

        shap_engine = SHAPEngine(
            str(ARTIFACT_DIR)
        )

        shap_engine.load(
            rf_model,
            FEATURE_NAMES
        )

        print(
            "SHAP engine loaded successfully."
        )

    except Exception as e:

        print(
            "SHAP ENGINE LOADING FAILED:",
            repr(e)
        )

        shap_engine = None


    # ========================================================
    # FINAL STATUS
    # ========================================================

    models_loaded = (
        rf_model is not None
        and scaler is not None
        and shap_engine is not None
        and dqn_agent is not None
    )

    print()
    print("=" * 60)

    if models_loaded:

        print(
            "ALL REQUIRED MODELS LOADED SUCCESSFULLY"
        )

    else:

        print(
            "WARNING: SOME REQUIRED MODELS ARE MISSING"
        )

    print(
        "RF   :",
        rf_model is not None
    )

    print(
        "Scaler:",
        scaler is not None
    )

    print(
        "SHAP :",
        shap_engine is not None
    )

    print(
        "DQN  :",
        dqn_agent is not None
    )

    print(
        "LSTM :",
        lstm_model is not None
    )

    print("=" * 60)


# ============================================================
# STARTUP
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    load_models()

    yield

    print(
        "ML engine shutting down."
    )


app = FastAPI(
    title="XRL-IDARS ML Engine",
    version="1.0.0",
    lifespan=lifespan
)


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {

        "status": "ok",

        "models_loaded":
            models_loaded,

        "rf_loaded":
            rf_model is not None,

        "scaler_loaded":
            scaler is not None,

        "shap_loaded":
            shap_engine is not None,

        "dqn_loaded":
            dqn_agent is not None,

        "lstm_loaded":
            lstm_model is not None,

    }


# ============================================================
# PREDICT
# ============================================================

@app.post("/predict")
def predict(
    request: PredictRequest
):

    if rf_model is None:

        raise HTTPException(
            status_code=503,
            detail="RF model is not loaded"
        )

    if scaler is None:

        raise HTTPException(
            status_code=503,
            detail="Scaler is not loaded"
        )


    try:

        # ----------------------------------------------------
        # Create feature vector in correct order
        # ----------------------------------------------------

        values = []

        for feature in FEATURE_NAMES:

            if feature not in request.features:

                raise ValueError(
                    f"Missing feature: {feature}"
                )

            values.append(
                request.features[feature]
            )


        X = np.asarray(
            values,
            dtype=np.float32
        ).reshape(
            1,
            -1
        )


        # ----------------------------------------------------
        # Scale
        # ----------------------------------------------------

        X_scaled = scaler.transform(
            X
        )


        # ----------------------------------------------------
        # RF prediction
        # ----------------------------------------------------

        predicted_class, probabilities, _ = (
            rf_model.predict(
                X_scaled
            )
        )


        # ----------------------------------------------------
        # SHAP
        # ----------------------------------------------------

        shap_result = None

        if shap_engine is not None:

            try:

                shap_result = (
                    shap_engine.explain(
                        X_scaled,
                        request.features
                    )
                )

            except Exception as e:

                shap_result = {
                    "error": str(e)
                }


        # ----------------------------------------------------
        # DQN action
        # ----------------------------------------------------

        dqn_result = None

        if dqn_agent is not None:

            try:

                state = [

                    float(
                        max(
                            probabilities.values()
                        )
                    ),

                    0.0,

                    float(
                        max(
                            probabilities.values()
                        )
                    ),

                    float(
                        request.features[
                            "flow_packets_per_s"
                        ]
                    ) / 10000.0,

                    float(
                        request.features[
                            "syn_count"
                        ]
                    ) / 100.0,

                    float(
                        request.env_state.get(
                            "historical_incident_count",
                            0.0
                        )
                    ),

                    float(
                        request.env_state.get(
                            "is_blocked",
                            0.0
                        )
                    ),

                ]

                state = np.clip(
                    state,
                    0.0,
                    1.0
                )

                action, q_values = (
                    dqn_agent.get_action(
                        state
                    )
                )

                dqn_result = {

                    "action": action,

                    "q_values": q_values

                }

            except Exception as e:

                dqn_result = {
                    "error": str(e)
                }


        # ----------------------------------------------------
        # Response
        # ----------------------------------------------------

        return {

            "status": "success",

            "flow_id":
                request.flow_id,

            "prediction":
                str(predicted_class),

            "probabilities":
                probabilities,

            "shap":
                shap_result,

            "dqn":
                dqn_result,

        }


    except Exception as e:

        print(
            "PREDICTION ERROR:",
            repr(e)
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {

        "service":
            "XRL-IDARS ML Engine",

        "status":
            "running"

    }