import os
import sys
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.feature_schema import FEATURE_SCHEMA, LABELS
from models.lstm_model import TemporalLSTM
from models.dqn_model import DQN

ARTIFACT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'artifacts')

def create_artifact_dir():
    if not os.path.exists(ARTIFACT_DIR):
        os.makedirs(ARTIFACT_DIR)

def load_and_clean_data(dataset_path):
    print("Loading datasets from", dataset_path)
    files = [f for f in os.listdir(dataset_path) if f.endswith('.csv')]
    if not files:
        raise FileNotFoundError(f"No CSV files found in {dataset_path}")
        
    dfs = []
    for f in files:
        print(f"Reading {f}...")
        df = pd.read_csv(os.path.join(dataset_path, f), encoding='cp1252', low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)
        
    df = pd.concat(dfs, ignore_index=True)
    print(f"Total rows before cleaning: {len(df)}")
    
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    print(f"Total rows after cleaning: {len(df)}")
    
    return df

def map_label(l):
    if l == 'BENIGN': return 'BENIGN'
    if l in ['DDoS', 'DoS Hulk', 'DoS GoldenEye', 'DoS slowloris', 'DoS Slowhttptest']: return 'DOS_ATTACK'
    if l == 'PortScan': return 'PORT_SCAN'
    if l in ['FTP-Patator', 'SSH-Patator']: return 'BRUTE_FORCE'
    if l == 'Bot': return 'BOTNET'
    if l == 'Infiltration': return 'INFILTRATION'
    if 'Web Attack' in l or l == 'Heartbleed': return 'WEB_ATTACK'
    return 'BENIGN'

def extract_features(df):
    print("Extracting canonical 10-feature schema...")
    out = pd.DataFrame()
    out['flow_duration_ms'] = df['Flow Duration'] / 1000.0
    out['flow_packets_per_s'] = df['Flow Packets/s']
    out['flow_bytes_per_s'] = df['Flow Bytes/s']
    out['packet_length_mean'] = df['Packet Length Mean']
    out['packet_length_std'] = df['Packet Length Std']
    out['syn_count'] = df['SYN Flag Count']
    out['ack_count'] = df['ACK Flag Count']
    out['rst_count'] = df['RST Flag Count']
    out['fin_count'] = df['FIN Flag Count']
    out['syn_ack_ratio'] = df['SYN Flag Count'] / df['ACK Flag Count'].clip(lower=1)
    
    out['Source IP'] = df['Source IP']
    out['Timestamp'] = pd.to_datetime(df['Timestamp'])
    out['Label'] = df['Label'].apply(map_label)
    
    return out

def train_models(data_path):
    create_artifact_dir()
    df = load_and_clean_data(data_path)
    df = extract_features(df)
    
    # Sort by Timestamp for sequence preservation
    df = df.sort_values('Timestamp').reset_index(drop=True)
    
    X = df[FEATURE_SCHEMA].values
    
    le = LabelEncoder()
    le.fit(LABELS)
    y = le.transform(df['Label'])
    joblib.dump(le, os.path.join(ARTIFACT_DIR, 'label_encoder.joblib'))
    
    # Time-Binned Stratified Split (Simplified for this script: standard GroupKFold by IP)
    print("Splitting dataset safely...")
    gkf = GroupKFold(n_splits=5)
    train_idx, test_idx = next(gkf.split(X, y, df['Source IP'].values))
    
    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    joblib.dump(scaler, os.path.join(ARTIFACT_DIR, 'scaler.joblib'))
    
    # 1. Random Forest Training
    print("Training Random Forest Classifier...")
    rf = RandomForestClassifier(n_estimators=50, class_weight='balanced', random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)
    
    print("\n[RF Evaluation]")
    y_pred = rf.predict(X_test_scaled)
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
    
    joblib.dump({'model': rf, 'label_encoder': le}, os.path.join(ARTIFACT_DIR, 'rf_model.joblib'))
    
    # 2. SHAP Explainer Background
    print("Saving SHAP background dataset...")
    bg_idx = np.random.choice(X_train_scaled.shape[0], min(200, X_train_scaled.shape[0]), replace=False)
    joblib.dump(X_train_scaled[bg_idx], os.path.join(ARTIFACT_DIR, 'shap_background.joblib'))
    
    # 3. LSTM Sequence Construction & Training
    print("Constructing T=5 LSTM sequences grouped by Source IP...")
    train_df = df.iloc[train_idx]
    
    xs_seq, ys_seq = [], []
    for _, group in train_df.groupby('Source IP'):
        vals = scaler.transform(group[FEATURE_SCHEMA].values)
        labels = le.transform(group['Label'])
        if len(vals) >= 5:
            for i in range(len(vals) - 4):
                xs_seq.append(vals[i:i+5])
                # Anomaly if any flow in sequence is not BENIGN (Label 0)
                is_anomaly = 1 if np.any(labels[i:i+5] != le.transform(['BENIGN'])[0]) else 0
                ys_seq.append(is_anomaly)
                
    X_seq = np.array(xs_seq)
    y_seq = np.array(ys_seq)
    print(f"Generated {len(X_seq)} sequences.")
    
    lstm_model = TemporalLSTM()
    if len(X_seq) > 0:
        criterion = nn.BCELoss()
        optimizer = torch.optim.Adam(lstm_model.parameters(), lr=0.001)
        dataset = TensorDataset(torch.tensor(X_seq, dtype=torch.float32), torch.tensor(y_seq, dtype=torch.float32).unsqueeze(1))
        loader = DataLoader(dataset, batch_size=256, shuffle=True)
        
        lstm_model.train()
        print("Training PyTorch LSTM...")
        for epoch in range(3):
            total_loss = 0
            for batch_x, batch_y in loader:
                optimizer.zero_grad()
                out = lstm_model(batch_x)
                loss = criterion(out, batch_y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            print(f"LSTM Epoch {epoch+1} Loss: {total_loss/len(loader):.4f}")
            
    torch.save(lstm_model.state_dict(), os.path.join(ARTIFACT_DIR, 'lstm_model.pt'))
    joblib.dump({'input_dim': 10, 'hidden_dim': 64, 'sequence_length': 5}, os.path.join(ARTIFACT_DIR, 'lstm_meta.joblib'))
    
    # 4. DQN Offline Configuration
    print("Saving Offline DQN weights...")
    dqn = DQN()
    torch.save(dqn.state_dict(), os.path.join(ARTIFACT_DIR, 'dqn_model.pt'))
    
    # Save Metadata
    joblib.dump({
        "status": "TRAINED",
        "feature_schema": FEATURE_SCHEMA,
        "dataset": data_path,
        "rf_accuracy": accuracy_score(y_test, y_pred)
    }, os.path.join(ARTIFACT_DIR, 'metadata.joblib'))
    
    print("✅ Training Pipeline Complete! Models ready for FastAPI inference.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python train_pipeline.py /path/to/cic_ids_2017/CSVs")
        sys.exit(1)
    train_models(sys.argv[1])
