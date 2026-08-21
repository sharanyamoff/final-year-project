import os
import sys
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Any

# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

ML_ENGINE_DIR = PROJECT_ROOT / "ml_engine"
MODELS_DIR = ML_ENGINE_DIR / "models"

print("=" * 60)
print("XRL-IDARS ML ENGINE STARTUP")
print("=" * 60)
print("PROJECT_ROOT:", PROJECT_ROOT)
print("MODELS_DIR:", MODELS_DIR)


# ============================================================
# IMPORTS
# ============================================================

try:
    from ml_engine.models.dqn_model import DQNAgent
    print("DQNAgent import: OK")
except Exception as e:
    DQNAgent = None
    print("DQNAgent import failed:", repr(e))

try:
    from ml_engine.explainability.shap_engine import SHAPEngine
    print("SHAPEngine import: OK")
except Exception as e:
    SHAPEngine = None
    print("SHAPEngine import failed:", repr(e))


# ============================================================
# GLOBAL MODEL OBJECTS
# ============================================================

rf_model = None
scaler = None
dqn_agent = None
shap_engine = None
lstm_model = None

models_loaded = False


# ============================================================
# REQUEST SCHEMAS
# ============================================================

class PredictRequest(BaseModel):
    flow_id: str = "unknown"

    features: Dict[str, float]

    sequence: List[Dict[str, float]] = []

    env_state: Dict[str, float] = {}


# ============================================================
# MODEL LOADING
# ============================================================

def load_models():

    global rf_model
    global scaler
    global dqn_agent
    global shap_engine
    global lstm_model
    global models_loaded

    print("\n" + "=" * 60)
    print("LOADING MODELS")
    print("=" * 60)

    # --------------------------------------------------------
    # Random Forest + scaler
    # --------------------------------------------------------

    try:
        import joblib

        rf_path = MODELS_DIR / "rf_model.pkl"
        scaler_path = MODELS_DIR / "lstm_scaler.pkl"

        if not rf_path.exists():
            raise FileNotFoundError(
                f"RF model not found: {rf_path}"
            )

        rf_artifact = joblib.load(rf_path)

        print("RF artifact type:", type(rf_artifact))

        # Support both:
        # 1. direct RandomForestClassifier
        # 2. {"model": ..., "label_encoder": ...}
        if isinstance(rf_artifact, dict):

            rf_model = rf_artifact.get("model")

            if rf_model is None:
                rf_model = rf_artifact.get("rf_model")

            if rf_model is None:
                raise ValueError(
                    "RF artifact does not contain 'model' or 'rf_model'"
                )

        else:
            rf_model = rf_artifact

        print("RF model loaded:", type(rf_model))

        if scaler_path.exists():
            scaler = joblib.load(scaler_path)
            print("Scaler loaded:", type(scaler))
        else:
            print("WARNING: scaler not found:", scaler_path)

    except Exception as e:
        print("RF MODEL LOADING FAILED:", repr(e))
        rf_model = None


    # --------------------------------------------------------
    # DQN
    # --------------------------------------------------------

    try:

        if DQNAgent is None:
            raise RuntimeError("DQNAgent import failed")

        dqn_agent = DQNAgent()

        # Try common load methods safely
        loaded = False

        for method_name in [
            "load",
            "load_model",
            "load_q_table"
        ]:

            if hasattr(dqn_agent, method_name):

                method = getattr(dqn_agent, method_name)

                try:
                    method(str(MODELS_DIR))
                    loaded = True
                    print(
                        f"DQN loaded successfully using {method_name}()"
                    )
                    break
                except Exception as e:
                    print(
                        f"DQN {method_name}() failed:",
                        repr(e)
                    )

        if not loaded:

            # Direct q-table fallback
            import numpy as np

            q_table_path = MODELS_DIR / "q_table.npy"

            if q_table_path.exists():

                q_table = np.load(
                    q_table_path,
                    allow_pickle=True
                )

                if hasattr(dqn_agent, "q_table"):
                    dqn_agent.q_table = q_table
                    loaded = True

                print("DQN q_table loaded:", q_table_path)

        if not loaded:
            print("WARNING: DQN could not be fully loaded")

    except Exception as e:
        print("DQN LOADING FAILED:", repr(e))
        dqn_agent = None


    # --------------------------------------------------------
    # LSTM
    # --------------------------------------------------------

    try:

        from tensorflow.keras.models import load_model

        lstm_candidates = [
            MODELS_DIR / "intrusion_lstm.keras",
            MODELS_DIR / "lstm_intrusion_detector.keras",
            ML_ENGINE_DIR / "lstm_intrusion_model.keras",
        ]

        lstm_path = None

        for candidate in lstm_candidates:
            if candidate.exists():
                lstm_path = candidate
                break

        if lstm_path is not None:

            lstm_model = load_model(str(lstm_path))

            print(
                "LSTM model loaded:",
                lstm_path
            )

        else:

            print(
                "WARNING: LSTM model not found"
            )

    except Exception as e:

        print(
            "WARNING: LSTM loading failed:",
            repr(e)
        )

        lstm_model = None


    # --------------------------------------------------------
    # SHAP
    # --------------------------------------------------------

    try:

        if SHAPEngine is None:
            raise RuntimeError(
                "SHAPEngine import failed"
            )

        if rf_model is None:
            raise RuntimeError(
                "RF model must be loaded before SHAP"
            )

        print("Creating ONE global SHAPEngine instance...")

        # IMPORTANT:
        # Use the same global instance for startup AND /predict.

        shap_engine = SHAPEngine(rf_model)

        print(
            "SHAPEngine object created:",
            type(shap_engine)
        )

        # Call load exactly once if available.
        if hasattr(shap_engine, "load"):

            try:

                shap_engine.load()

                print(
                    "SHAP engine loaded successfully."
                )

            except TypeError:

                # Some implementations expect model/scaler
                try:

                    shap_engine.load(
                        rf_model,
                        scaler
                    )

                    print(
                        "SHAP engine loaded successfully "
                        "with RF + scaler."
                    )

                except Exception as e:

                    print(
                        "SHAP load failed:",
                        repr(e)
                    )

        else:

            print(
                "WARNING: SHAPEngine has no load() method"
            )

    except Exception as e:

        print(
            "SHAP ENGINE LOADING FAILED:",
            repr(e)
        )

        shap_engine = None


    # --------------------------------------------------------
    # FINAL STATUS
    # --------------------------------------------------------

    models_loaded = (
        rf_model is not None
        and shap_engine is not None
    )

    print("\n" + "=" * 60)

    if models_loaded:
        print("ALL REQUIRED MODELS LOADED SUCCESSFULLY")
    else:
        print("WARNING: SOME MODELS ARE NOT AVAILABLE")

    print("RF:", rf_model is not None)
    print("SHAP:", shap_engine is not None)
    print("DQN:", dqn_agent is not None)
    print("LSTM:", lstm_model is not None)

    print("=" * 60)


# ============================================================
# SHAP PREDICTION
# ============================================================

def run_shap(features: Dict[str, float]) -> Any:

    global shap_engine

    if shap_engine is None:

        raise RuntimeError(
            "SHAP engine is not loaded."
        )

    # IMPORTANT:
    # The same global object loaded during startup is used here.

    feature_values = list(features.values())

    # Try common SHAPEngine interfaces.

    if hasattr(shap_engine, "explain"):

        return shap_engine.explain(
            feature_values
        )

    if hasattr(shap_engine, "predict"):

        return shap_engine.predict(
            feature_values
        )

    if hasattr(shap_engine, "shap_values"):

        return shap_engine.shap_values(
            feature_values
        )

    raise RuntimeError(
        "SHAPEngine does not expose "
        "explain(), predict(), or shap_values()."
    )


# ============================================================
# FASTAPI LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    load_models()

    yield

    print("Shutting down ML engine...")


# ============================================================
# FASTAPI APP
# ============================================================

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
        "models_loaded": models_loaded,
        "rf_loaded": rf_model is not None,
        "shap_loaded": shap_engine is not None,
        "dqn_loaded": dqn_agent is not None,
        "lstm_loaded": lstm_model is not None
    }


# ============================================================
# PREDICT
# ============================================================

@app.post("/predict")
def predict(request: PredictRequest):

    if rf_model is None:

        raise HTTPException(
            status_code=503,
            detail="RF model is not loaded"
        )

    features = request.features

    try:

        # ----------------------------------------------------
        # Prepare features
        # ----------------------------------------------------

        feature_values = list(features.values())

        import numpy as np

        X = np.asarray(
            feature_values,
            dtype=float
        ).reshape(1, -1)

        # ----------------------------------------------------
        # Scaling
        # ----------------------------------------------------

        X_scaled = X

        if scaler is not None:

            try:
                X_scaled = scaler.transform(X)
            except Exception as e:

                print(
                    "Scaler warning:",
                    repr(e)
                )

        # ----------------------------------------------------
        # RF prediction
        # ----------------------------------------------------

        prediction = rf_model.predict(
            X_scaled
        )

        predicted_class = prediction[0]

        # ----------------------------------------------------
        # Probability
        # ----------------------------------------------------

        confidence = None

        if hasattr(
            rf_model,
            "predict_proba"
        ):

            try:

                probabilities = (
                    rf_model.predict_proba(X_scaled)
                )

                confidence = float(
                    probabilities.max()
                )

            except Exception as e:

                print(
                    "Probability warning:",
                    repr(e)
                )

        # ----------------------------------------------------
        # SHAP
        # ----------------------------------------------------

        shap_result = None

        try:

            shap_result = run_shap(
                features
            )

        except Exception as e:

            print(
                "SHAP inference failed:",
                repr(e)
            )

            # Do NOT make the whole prediction fail
            # just because SHAP explanation failed.

            shap_result = {
                "error": str(e)
            }

        # ----------------------------------------------------
        # Response
        # ----------------------------------------------------

        return {
            "status": "success",
            "flow_id": request.flow_id,

            "prediction": (
                predicted_class.item()
                if hasattr(
                    predicted_class,
                    "item"
                )
                else predicted_class
            ),

            "confidence": confidence,

            "shap": shap_result,

            "env_state": request.env_state
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
        "service": "XRL-IDARS ML Engine",
        "status": "running"
    }