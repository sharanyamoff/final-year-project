from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
import joblib
import numpy as np

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.feature_schema import FEATURE_SCHEMA
from models.rf_model import RFModel
from models.lstm_model import LSTMWrapper
from models.dqn_model import DQNAgent
from explainability.shap_engine import SHAPEngine

app = FastAPI(title="XRL-IDARS ML Engine")

ARTIFACT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'artifacts')

rf = RFModel(ARTIFACT_DIR)
lstm = LSTMWrapper(ARTIFACT_DIR)
dqn = DQNAgent(ARTIFACT_DIR)
shap_engine = SHAPEngine(ARTIFACT_DIR)
scaler = None

models_loaded = False

class PredictRequest(BaseModel):
    flow_id: str
    features: Dict[str, float]
    sequence: List[Dict[str, float]]
    env_state: Dict[str, float]

@app.on_event("startup")
def load_models():
    global models_loaded, scaler
    try:
        scaler_path = os.path.join(ARTIFACT_DIR, 'scaler.joblib')
        if not os.path.exists(scaler_path):
            print("WARNING: Models not trained. Run train_pipeline.py first.")
            return
            
        scaler = joblib.load(scaler_path)
        rf.load()
        lstm.load()
        dqn.load()
        shap_engine.load(rf, FEATURE_SCHEMA)
        models_loaded = True
        print("All models loaded successfully.")
    except Exception as e:
        print(f"Failed to load models: {e}")
        models_loaded = False

@app.get("/health")
def health():
    return {"status": "ok", "models_loaded": models_loaded}

@app.get("/model-info")
def model_info():
    if not models_loaded:
        return {"status": "MODEL_NOT_TRAINED"}
    
    meta_path = os.path.join(ARTIFACT_DIR, 'metadata.joblib')
    if os.path.exists(meta_path):
        meta = joblib.load(meta_path)
        return {"status": "MODEL_LOADED", "metadata": meta}
    return {"status": "MODEL_LOADED", "metadata": "unknown"}

@app.post("/predict")
def predict(req: PredictRequest):
    if not models_loaded:
        raise HTTPException(status_code=503, detail="MODEL_NOT_TRAINED or MODEL_INFERENCE_ERROR")
        
    for f in FEATURE_SCHEMA:
        if f not in req.features:
            raise HTTPException(status_code=400, detail=f"Missing feature: {f}")
            
    curr_vec = np.array([[req.features[f] for f in FEATURE_SCHEMA]])
    curr_scaled = scaler.transform(curr_vec)
    
    rf_class, rf_probs, rf_raw_probs = rf.predict(curr_scaled)
    max_rf_prob = float(np.max(rf_raw_probs))
    
    shap_out = shap_engine.explain(curr_scaled, curr_vec[0])
    
    lstm_score = 0.0
    lstm_status = "PENDING"
    if len(req.sequence) == 5:
        seq_vec = []
        for s in req.sequence:
            for f in FEATURE_SCHEMA:
                if f not in s:
                    raise HTTPException(status_code=400, detail=f"Missing feature in sequence: {f}")
            seq_vec.append([s[f] for f in FEATURE_SCHEMA])
        
        seq_scaled = scaler.transform(np.array(seq_vec))
        lstm_score = lstm.predict(np.expand_dims(seq_scaled, 0))
        lstm_status = "EVALUATED"
    elif len(req.sequence) > 5:
        raise HTTPException(status_code=400, detail="Sequence length exceeds 5")
        
    risk_score = 0.6 * max_rf_prob + 0.4 * lstm_score if lstm_status == "EVALUATED" else max_rf_prob
    
    dqn_state = [
        max_rf_prob,
        lstm_score,
        risk_score,
        req.features.get('flow_packets_per_s', 0.0),
        req.features.get('syn_count', 0.0),
        req.env_state.get('historical_incident_count', 0.0),
        req.env_state.get('is_blocked', 0.0)
    ]
    
    dqn_action, dqn_q_vals = dqn.get_action(dqn_state)
    
    return {
        "rf": {
            "predicted_class": rf_class,
            "probabilities": rf_probs
        },
        "lstm": {
            "status": lstm_status,
            "anomaly_score": lstm_score
        },
        "risk_score": float(risk_score),
        "shap": shap_out,
        "dqn": {
            "action": dqn_action,
            "q_values": dqn_q_vals
        }
    }
