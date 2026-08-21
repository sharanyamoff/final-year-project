import os
import sys
import time
import pandas as pd
import numpy as np
import joblib
import random
from collections import Counter
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import torch
import torch.nn as nn
import torch.optim as optim
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
    print(f"Loading datasets from {dataset_path}...")
    files = [f for f in os.listdir(dataset_path) if f.endswith('.csv')]
    if not files:
        raise FileNotFoundError(f"No CSV files found in {dataset_path}. Please download CIC-IDS2017.")
        
    dfs = []
    for f in files:
        print(f"Reading {f}...")
        df = pd.read_csv(os.path.join(dataset_path, f), encoding='cp1252', low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)
        
    df = pd.concat(dfs, ignore_index=True)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
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
    start_time = time.time()
    create_artifact_dir()
    
    df = load_and_clean_data(data_path)
    df = extract_features(df)
    df = df.sort_values('Timestamp').reset_index(drop=True)
    
    X = df[FEATURE_SCHEMA].values
    
    le = LabelEncoder()
    le.fit(LABELS)
    y = le.transform(df['Label'])
    
    # Quality Check
    class_counts = Counter(y)
    print("\n--- Class Distribution ---")
    for cls_idx, count in class_counts.items():
        print(f"{le.classes_[cls_idx]}: {count}")
        if count < 50 and le.classes_[cls_idx] != 'BENIGN':
            raise ValueError(f"Insufficient samples for class {le.classes_[cls_idx]} ({count}). Minimum 50 required.")
            
    # Leakage-safe GroupKFold
    print("\n--- Splitting Dataset ---")
    gkf = GroupKFold(n_splits=5)
    train_idx, test_idx = next(gkf.split(X, y, df['Source IP'].values))
    
    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    
    print("Fitting Scaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    joblib.dump(le, os.path.join(ARTIFACT_DIR, 'label_encoder.joblib'))
    joblib.dump(scaler, os.path.join(ARTIFACT_DIR, 'scaler.joblib'))
    
    # 1. Random Forest Training
    print("\n--- Training Random Forest ---")
    rf_start = time.time()
    rf = RandomForestClassifier(n_estimators=50, class_weight='balanced', random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)
    rf_duration = time.time() - rf_start
    
    y_pred = rf.predict(X_test_scaled)
    rf_acc = accuracy_score(y_test, y_pred)
    rf_report = classification_report(y_test, y_pred, target_names=le.inverse_transform(np.unique(y_test)), output_dict=True)
    rf_conf_matrix = confusion_matrix(y_test, y_pred)
    
    joblib.dump({'model': rf, 'label_encoder': le}, os.path.join(ARTIFACT_DIR, 'rf_model.joblib'))
    
    # 2. SHAP Background
    bg_idx = np.random.choice(X_train_scaled.shape[0], min(200, X_train_scaled.shape[0]), replace=False)
    joblib.dump(X_train_scaled[bg_idx], os.path.join(ARTIFACT_DIR, 'shap_background.joblib'))
    
    # 3. LSTM Temporal Sequences
    print("\n--- Constructing LSTM Sequences ---")
    train_df = df.iloc[train_idx]
    
    xs_seq, ys_seq = [], []
    for _, group in train_df.groupby('Source IP'):
        vals = scaler.transform(group[FEATURE_SCHEMA].values)
        labels = le.transform(group['Label'])
        if len(vals) >= 5:
            for i in range(len(vals) - 4):
                xs_seq.append(vals[i:i+5])
                is_anomaly = 1 if np.any(labels[i:i+5] != le.transform(['BENIGN'])[0]) else 0
                ys_seq.append(is_anomaly)
                
    X_seq = np.array(xs_seq)
    y_seq = np.array(ys_seq)
    
    lstm_model = TemporalLSTM()
    lstm_duration = 0
    lstm_loss = 0.0
    
    if len(X_seq) > 0:
        lstm_start = time.time()
        criterion = nn.BCELoss()
        optimizer = optim.Adam(lstm_model.parameters(), lr=0.001)
        dataset = TensorDataset(torch.tensor(X_seq, dtype=torch.float32), torch.tensor(y_seq, dtype=torch.float32).unsqueeze(1))
        loader = DataLoader(dataset, batch_size=256, shuffle=True)
        
        lstm_model.train()
        for epoch in range(3):
            total_loss = 0
            for batch_x, batch_y in loader:
                optimizer.zero_grad()
                out = lstm_model(batch_x)
                loss = criterion(out, batch_y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            lstm_loss = total_loss/len(loader)
            print(f"LSTM Epoch {epoch+1} Loss: {lstm_loss:.4f}")
        lstm_duration = time.time() - lstm_start
        torch.save(lstm_model.state_dict(), os.path.join(ARTIFACT_DIR, 'lstm_model.pt'))
        joblib.dump({'input_dim': 10, 'hidden_dim': 64, 'sequence_length': 5}, os.path.join(ARTIFACT_DIR, 'lstm_meta.joblib'))
    else:
        raise ValueError("No valid LSTM sequences (T=5) could be generated. Dataset too small.")

    # 4. Genuine DQN Offline Training
    print("\n--- Training DQN Offline Environment ---")
    dqn_start = time.time()
    
    lstm_model.eval()
    with torch.no_grad():
        lstm_preds = lstm_model(torch.tensor(X_seq, dtype=torch.float32)).numpy().flatten()
        
    curr_features = X_seq[:, -1, :] 
    rf_probs = rf.predict_proba(curr_features)
    rf_max = np.max(rf_probs, axis=1)
    risk_scores = 0.6 * rf_max + 0.4 * lstm_preds
    
    curr_features_unscaled = scaler.inverse_transform(curr_features)
    pkts_s = curr_features_unscaled[:, 1]
    syn_c = curr_features_unscaled[:, 5]
    
    dqn = DQN()
    target_dqn = DQN()
    target_dqn.load_state_dict(dqn.state_dict())
    optimizer_dqn = optim.Adam(dqn.parameters(), lr=0.001)
    criterion_dqn = nn.MSELoss()
    
    epsilon = 1.0
    epsilon_min = 0.05
    epsilon_decay = 0.995
    gamma = 0.99
    
    # Offline RL loop using extracted states
    # Actions: 0=ALLOW, 1=ALERT, 2=BLOCK
    dqn_loss = 0
    episodes = min(5000, len(X_seq)) # Train on a subset of transitions for time
    
    for i in range(episodes):
        state = np.array([rf_max[i], lstm_preds[i], risk_scores[i], pkts_s[i], syn_c[i], 0.0, 0.0])
        state_t = torch.tensor(state, dtype=torch.float32).unsqueeze(0)
        
        if random.random() < epsilon:
            action = random.randint(0, 2)
        else:
            with torch.no_grad():
                q_vals = dqn(state_t)
            action = int(torch.argmax(q_vals).item())
            
        # Environment Reward Logic
        is_attack = y_seq[i] == 1
        
        if action == 2: # BLOCK
            reward = 10 if is_attack else -18
        elif action == 1: # ALERT
            reward = 5 if is_attack else -2
        else: # ALLOW
            reward = 5 if not is_attack else -25
            
        # Simplified Next State (assuming stateless environment for instant flow block)
        next_state = state.copy()
        
        # Bellman update
        next_state_t = torch.tensor(next_state, dtype=torch.float32).unsqueeze(0)
        with torch.no_grad():
            target_q = reward + gamma * torch.max(target_dqn(next_state_t)).item()
            
        current_q = dqn(state_t)[0][action]
        loss = criterion_dqn(current_q, torch.tensor(target_q, dtype=torch.float32))
        
        optimizer_dqn.zero_grad()
        loss.backward()
        optimizer_dqn.step()
        dqn_loss = loss.item()
        
        if i % 1000 == 0:
            target_dqn.load_state_dict(dqn.state_dict())
            epsilon = max(epsilon_min, epsilon * epsilon_decay)
            
    torch.save(dqn.state_dict(), os.path.join(ARTIFACT_DIR, 'dqn_model.pt'))
    dqn_duration = time.time() - dqn_start
    
    # 5. Metadata and Final Summary
    total_duration = time.time() - start_time
    
    metadata = {
        "status": "TRAINED",
        "feature_schema": FEATURE_SCHEMA,
        "dataset": data_path,
        "rf_accuracy": rf_acc,
        "lstm_loss": lstm_loss,
        "dqn_final_loss": dqn_loss,
        "training_duration_s": total_duration
    }
    joblib.dump(metadata, os.path.join(ARTIFACT_DIR, 'metadata.joblib'))
    
    print("\n=======================================================")
    print("                TRAINING SUMMARY REPORT                ")
    print("=======================================================")
    print(f"Total Samples Processed : {len(df)}")
    print(f"Total Train Split       : {len(X_train)}")
    print(f"Total Test Split        : {len(X_test)}")
    print(f"Total T=5 Sequences     : {len(X_seq)}")
    print("\n[Random Forest Metrics]")
    print(f"Accuracy                : {rf_acc*100:.2f}%")
    print(f"Training Time           : {rf_duration:.2f} s")
    print("Confusion Matrix:")
    print(rf_conf_matrix)
    print("\n[LSTM Metrics]")
    print(f"Final BCE Loss          : {lstm_loss:.4f}")
    print(f"Training Time           : {lstm_duration:.2f} s")
    print("\n[DQN Agent Metrics]")
    print(f"Final MSE Loss          : {dqn_loss:.4f}")
    print(f"Final Epsilon           : {epsilon:.4f}")
    print(f"Training Time           : {dqn_duration:.2f} s")
    print("\n[Artifacts Saved to ml_engine/artifacts/]")
    print("- rf_model.joblib")
    print("- lstm_model.pt")
    print("- dqn_model.pt")
    print("- scaler.joblib")
    print("- label_encoder.joblib")
    print("- shap_background.joblib")
    print("- lstm_meta.joblib")
    print("- metadata.joblib")
    print(f"\nTotal Pipeline Duration : {total_duration:.2f} seconds")
    print("=======================================================")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python train_pipeline.py /path/to/cic_ids_2017/CSVs")
        sys.exit(1)
    train_models(sys.argv[1])
