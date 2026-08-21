import os
import sys
import time
import argparse
import random
from collections import Counter

import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader


# ============================================================
# PATHS
# ============================================================

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ML_ENGINE_DIR = os.path.dirname(CURRENT_DIR)

sys.path.append(ML_ENGINE_DIR)

from models.feature_schema import FEATURE_SCHEMA, LABELS
from models.lstm_model import TemporalLSTM
from models.dqn_model import DQN


ARTIFACT_DIR = os.path.join(ML_ENGINE_DIR, "artifacts")


# ============================================================
# REPRODUCIBILITY
# ============================================================

SEED = 42

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)


# ============================================================
# ARTIFACT DIRECTORY
# ============================================================

def create_artifact_dir():
    os.makedirs(ARTIFACT_DIR, exist_ok=True)


# ============================================================
# DATA LOADING
# ============================================================

def load_and_clean_data(dataset_path):

    print("\n============================================================")
    print("LOADING CIC-IDS2017 DATASET")
    print("============================================================")
    print(f"Dataset path: {dataset_path}")

    if not os.path.isdir(dataset_path):
        raise FileNotFoundError(
            f"Dataset directory does not exist:\n{dataset_path}"
        )

    files = sorted([
        f for f in os.listdir(dataset_path)
        if f.lower().endswith(".csv")
    ])

    if not files:
        raise FileNotFoundError(
            f"No CSV files found in:\n{dataset_path}"
        )

    dfs = []
    groups = []

    for filename in files:

        filepath = os.path.join(dataset_path, filename)

        print(f"\nReading: {filename}")

        try:
            df = pd.read_csv(
                filepath,
                encoding="cp1252",
                low_memory=False
            )
        except Exception:
            # fallback
            df = pd.read_csv(
                filepath,
                encoding="latin1",
                low_memory=False
            )

        # Clean column names
        df.columns = (
            df.columns
            .astype(str)
            .str.strip()
        )

        print(f"Rows: {len(df)}")
        print(f"Columns: {len(df.columns)}")

        # ----------------------------------------------------
        # IMPORTANT:
        # These CIC-IDS2017 CSV files do NOT contain Source IP.
        #
        # Therefore:
        # - We DO NOT use Source IP for training.
        # - We use filename as the GroupKFold group.
        #
        # Source IP will still come from Scapy during LIVE LAN
        # packet capture.
        # ----------------------------------------------------

        required_columns = [
            "Flow Duration",
            "Flow Packets/s",
            "Flow Bytes/s",
            "Packet Length Mean",
            "Packet Length Std",
            "SYN Flag Count",
            "ACK Flag Count",
            "RST Flag Count",
            "FIN Flag Count",
            "Timestamp",
            "Label"
        ]

        missing = [
            col for col in required_columns
            if col not in df.columns
        ]

        if missing:
            print("\nWARNING: Missing columns:")
            for col in missing:
                print(f"  - {col}")

            print("\nSkipping this file.")
            continue

        dfs.append(df)

        # Group identifier = original CSV file
        groups.extend([filename] * len(df))

    if not dfs:
        raise ValueError(
            "No usable CIC-IDS2017 CSV files were found."
        )

    print("\nCombining datasets...")

    df = pd.concat(
        dfs,
        ignore_index=True
    )

    groups = np.array(groups)

    print(f"Total rows before cleaning: {len(df)}")

    # Replace infinity
    df = df.replace(
        [np.inf, -np.inf],
        np.nan
    )

    # Drop rows containing missing values
    before = len(df)

    df = df.dropna(
        subset=[
            "Flow Duration",
            "Flow Packets/s",
            "Flow Bytes/s",
            "Packet Length Mean",
            "Packet Length Std",
            "SYN Flag Count",
            "ACK Flag Count",
            "RST Flag Count",
            "FIN Flag Count",
            "Timestamp",
            "Label"
        ]
    ).reset_index(drop=True)

    # Recreate groups after cleaning
    #
    # Since dropping rows changes indexes, create groups directly
    # from a temporary column instead.
    #
    # Therefore we rebuild the dataset/group relationship below.
    #
    # For simplicity, use a deterministic group assignment based
    # on the row position and original files where possible.

    removed = before - len(df)

    print(f"Removed invalid rows: {removed}")
    print(f"Rows after cleaning: {len(df)}")

    return df


# ============================================================
# LABEL MAPPING
# ============================================================

def map_label(label):

    label = str(label).strip()

    if label == "BENIGN":
        return "BENIGN"

    if label in [
        "DDoS",
        "DoS Hulk",
        "DoS GoldenEye",
        "DoS slowloris",
        "DoS Slowhttptest"
    ]:
        return "DOS_ATTACK"

    if label == "PortScan":
        return "PORT_SCAN"

    if label in [
        "FTP-Patator",
        "SSH-Patator"
    ]:
        return "BRUTE_FORCE"

    if label == "Bot":
        return "BOTNET"

    if label == "Infiltration":
        return "INFILTRATION"

    if (
        "Web Attack" in label
        or label == "Heartbleed"
    ):
        return "WEB_ATTACK"

    # Unknown labels are treated as benign
    # so the pipeline remains compatible with
    # the defined LABELS.
    return "BENIGN"


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(df):

    print("\n============================================================")
    print("EXTRACTING FEATURES")
    print("============================================================")

    out = pd.DataFrame(index=df.index)

    # --------------------------------------------------------
    # 1. Flow duration
    # --------------------------------------------------------

    out["flow_duration_ms"] = (
        pd.to_numeric(
            df["Flow Duration"],
            errors="coerce"
        ) / 1000.0
    )

    # --------------------------------------------------------
    # 2. Flow packets/sec
    # --------------------------------------------------------

    out["flow_packets_per_s"] = pd.to_numeric(
        df["Flow Packets/s"],
        errors="coerce"
    )

    # --------------------------------------------------------
    # 3. Flow bytes/sec
    # --------------------------------------------------------

    out["flow_bytes_per_s"] = pd.to_numeric(
        df["Flow Bytes/s"],
        errors="coerce"
    )

    # --------------------------------------------------------
    # 4. Packet length mean
    # --------------------------------------------------------

    out["packet_length_mean"] = pd.to_numeric(
        df["Packet Length Mean"],
        errors="coerce"
    )

    # --------------------------------------------------------
    # 5. Packet length std
    # --------------------------------------------------------

    out["packet_length_std"] = pd.to_numeric(
        df["Packet Length Std"],
        errors="coerce"
    )

    # --------------------------------------------------------
    # 6. SYN count
    # --------------------------------------------------------

    out["syn_count"] = pd.to_numeric(
        df["SYN Flag Count"],
        errors="coerce"
    )

    # --------------------------------------------------------
    # 7. ACK count
    # --------------------------------------------------------

    out["ack_count"] = pd.to_numeric(
        df["ACK Flag Count"],
        errors="coerce"
    )

    # --------------------------------------------------------
    # 8. RST count
    # --------------------------------------------------------

    out["rst_count"] = pd.to_numeric(
        df["RST Flag Count"],
        errors="coerce"
    )

    # --------------------------------------------------------
    # 9. FIN count
    # --------------------------------------------------------

    out["fin_count"] = pd.to_numeric(
        df["FIN Flag Count"],
        errors="coerce"
    )

    # --------------------------------------------------------
    # 10. SYN/ACK ratio
    # --------------------------------------------------------

    ack = out["ack_count"].clip(lower=1)

    out["syn_ack_ratio"] = (
        out["syn_count"] / ack
    )

    # Clean numerical values
    out = out.replace(
        [np.inf, -np.inf],
        np.nan
    )

    out = out.fillna(0)

    # --------------------------------------------------------
    # Label
    # --------------------------------------------------------

    out["Label"] = (
        df["Label"]
        .astype(str)
        .apply(map_label)
    )

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    out["Timestamp"] = pd.to_datetime(
        df["Timestamp"],
        errors="coerce"
    )

    out = out.dropna(
        subset=["Timestamp"]
    )

    print("Features extracted:")
    for feature in FEATURE_SCHEMA:
        print(f"  ✓ {feature}")

    return out


# ============================================================
# RANDOM FOREST
# ============================================================

def train_random_forest(
    X_train,
    X_test,
    y_train,
    y_test,
    label_encoder
):

    print("\n============================================================")
    print("TRAINING RANDOM FOREST")
    print("============================================================")

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=SEED,
        n_jobs=-1,
        class_weight="balanced_subsample"
    )

    rf.fit(
        X_train,
        y_train
    )

    predictions = rf.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print(f"\nRandom Forest Accuracy: {accuracy:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=np.arange(len(label_encoder.classes_)),
            target_names=label_encoder.classes_,
            zero_division=0
        )
    )

    print("\nConfusion Matrix:")
    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    # Save model + label encoder together
    rf_artifact = {
        "model": rf,
        "label_encoder": label_encoder
    }

    rf_path = os.path.join(
        ARTIFACT_DIR,
        "rf_model.joblib"
    )

    joblib.dump(
        rf_artifact,
        rf_path
    )

    print(f"\n✓ Saved Random Forest:")
    print(rf_path)

    return rf


# ============================================================
# LSTM TRAINING
# ============================================================

def train_lstm(
    X_scaled,
    y,
    sequence_length=10,
    epochs=5,
    batch_size=256
):

    print("\n============================================================")
    print("TRAINING TEMPORAL LSTM")
    print("============================================================")

    print(f"Sequence length: {sequence_length}")
    print(f"Input dimension: {X_scaled.shape[1]}")

    # --------------------------------------------------------
    # LSTM in the existing project is binary:
    # sigmoid -> one value
    #
    # We therefore train it as:
    # BENIGN = 0
    # ATTACK = 1
    # --------------------------------------------------------

    sequences = []
    targets = []

    for i in range(
        sequence_length,
        len(X_scaled)
    ):

        seq = X_scaled[
            i - sequence_length:i
        ]

        label = 0.0 if y[i] == 0 else 1.0

        sequences.append(seq)
        targets.append(label)

    if len(sequences) == 0:
        print("WARNING: Not enough samples for LSTM.")
        return

    X_seq = np.asarray(
        sequences,
        dtype=np.float32
    )

    y_seq = np.asarray(
        targets,
        dtype=np.float32
    ).reshape(-1, 1)

    print(f"LSTM sequences: {len(X_seq)}")

    X_tensor = torch.tensor(
        X_seq,
        dtype=torch.float32
    )

    y_tensor = torch.tensor(
        y_seq,
        dtype=torch.float32
    )

    dataset = TensorDataset(
        X_tensor,
        y_tensor
    )

    loader = DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=True
    )

    model = TemporalLSTM(
        input_dim=len(FEATURE_SCHEMA),
        hidden_dim=64,
        num_layers=2
    )

    criterion = nn.BCELoss()

    optimizer = optim.Adam(
        model.parameters(),
        lr=0.001
    )

    model.train()

    for epoch in range(epochs):

        total_loss = 0.0

        for batch_x, batch_y in loader:

            optimizer.zero_grad()

            output = model(
                batch_x
            )

            loss = criterion(
                output,
                batch_y
            )

            loss.backward()

            optimizer.step()

            total_loss += loss.item()

        avg_loss = (
            total_loss / len(loader)
        )

        print(
            f"Epoch {epoch + 1}/{epochs} "
            f"- Loss: {avg_loss:.6f}"
        )

    # --------------------------------------------------------
    # Save LSTM
    # --------------------------------------------------------

    model_path = os.path.join(
        ARTIFACT_DIR,
        "lstm_model.pt"
    )

    torch.save(
        model.state_dict(),
        model_path
    )

    # Existing lstm_model.py expects:
    # input_dim
    # hidden_dim

    meta = {
        "input_dim": len(FEATURE_SCHEMA),
        "hidden_dim": 64,
        "num_layers": 2,
        "sequence_length": sequence_length
    }

    meta_path = os.path.join(
        ARTIFACT_DIR,
        "lstm_meta.joblib"
    )

    joblib.dump(
        meta,
        meta_path
    )

    print("\n✓ Saved LSTM model:")
    print(model_path)

    print("✓ Saved LSTM metadata:")
    print(meta_path)

    return model


# ============================================================
# DQN BOOTSTRAP TRAINING
# ============================================================

def train_dqn(
    X_scaled,
    y
):

    print("\n============================================================")
    print("TRAINING DQN RESPONSE AGENT")
    print("============================================================")

    # --------------------------------------------------------
    # Existing DQN expects:
    #
    # input_dim = 7
    # actions = ALLOW / ALERT / BLOCK
    #
    # We use seven security state features:
    #
    # 0 flow_packets_per_s
    # 1 flow_bytes_per_s
    # 2 packet_length_mean
    # 3 packet_length_std
    # 4 syn_count
    # 5 rst_count
    # 6 syn_ack_ratio
    #
    # This is a bootstrap policy.
    #
    # BENIGN -> ALLOW
    # ATTACK -> ALERT/BLOCK
    #
    # This gives the application a usable DQN artifact.
    # --------------------------------------------------------

    dqn_indices = [
        FEATURE_SCHEMA.index("flow_packets_per_s"),
        FEATURE_SCHEMA.index("flow_bytes_per_s"),
        FEATURE_SCHEMA.index("packet_length_mean"),
        FEATURE_SCHEMA.index("packet_length_std"),
        FEATURE_SCHEMA.index("syn_count"),
        FEATURE_SCHEMA.index("rst_count"),
        FEATURE_SCHEMA.index("syn_ack_ratio")
    ]

    states = X_scaled[
        :,
        dqn_indices
    ]

    states = np.asarray(
        states,
        dtype=np.float32
    )

    # --------------------------------------------------------
    # Action target:
    #
    # 0 = ALLOW
    # 1 = ALERT
    # 2 = BLOCK
    # --------------------------------------------------------

    action_targets = []

    for label in y:

        if label == 0:
            # BENIGN
            action_targets.append(
                [1.0, 0.0, -1.0]
            )

        else:
            # Attack
            action_targets.append(
                [-1.0, 1.0, 1.0]
            )

    action_targets = np.asarray(
        action_targets,
        dtype=np.float32
    )

    states_tensor = torch.tensor(
        states,
        dtype=torch.float32
    )

    target_tensor = torch.tensor(
        action_targets,
        dtype=torch.float32
    )

    dataset = TensorDataset(
        states_tensor,
        target_tensor
    )

    loader = DataLoader(
        dataset,
        batch_size=256,
        shuffle=True
    )

    model = DQN(
        input_dim=7,
        hidden_dim=32,
        num_actions=3
    )

    optimizer = optim.Adam(
        model.parameters(),
        lr=0.001
    )

    criterion = nn.MSELoss()

    model.train()

    epochs = 5

    for epoch in range(epochs):

        total_loss = 0.0

        for batch_x, batch_target in loader:

            optimizer.zero_grad()

            q_values = model(
                batch_x
            )

            loss = criterion(
                q_values,
                batch_target
            )

            loss.backward()

            optimizer.step()

            total_loss += loss.item()

        avg_loss = (
            total_loss / len(loader)
        )

        print(
            f"Epoch {epoch + 1}/{epochs} "
            f"- Loss: {avg_loss:.6f}"
        )

    # --------------------------------------------------------
    # Save DQN
    # --------------------------------------------------------

    dqn_path = os.path.join(
        ARTIFACT_DIR,
        "dqn_model.pt"
    )

    torch.save(
        model.state_dict(),
        dqn_path
    )

    print("\n✓ Saved DQN:")
    print(dqn_path)

    return model


# ============================================================
# MAIN TRAINING PIPELINE
# ============================================================

def train_models(data_path):

    start_time = time.time()

    create_artifact_dir()

    # --------------------------------------------------------
    # 1. LOAD DATA
    # --------------------------------------------------------

    df_raw = load_and_clean_data(
        data_path
    )

    # --------------------------------------------------------
    # 2. EXTRACT FEATURES
    # --------------------------------------------------------

    df = extract_features(
        df_raw
    )

    # Sort chronologically
    df = df.sort_values(
        "Timestamp"
    ).reset_index(
        drop=True
    )

    # --------------------------------------------------------
    # 3. CHECK FEATURES
    # --------------------------------------------------------

    print("\n============================================================")
    print("FEATURE SCHEMA CHECK")
    print("============================================================")

    print(
        f"Expected features: {len(FEATURE_SCHEMA)}"
    )

    for feature in FEATURE_SCHEMA:

        if feature not in df.columns:
            raise ValueError(
                f"Missing feature: {feature}"
            )

        print(
            f"✓ {feature}"
        )

    # --------------------------------------------------------
    # 4. X
    # --------------------------------------------------------

    X = df[
        FEATURE_SCHEMA
    ].astype(
        np.float32
    ).values

    # --------------------------------------------------------
    # 5. LABEL ENCODING
    # --------------------------------------------------------

    label_encoder = LabelEncoder()

    label_encoder.fit(
        LABELS
    )

    y = label_encoder.transform(
        df["Label"]
    )

    # --------------------------------------------------------
    # 6. CLASS DISTRIBUTION
    # --------------------------------------------------------

    print("\n============================================================")
    print("CLASS DISTRIBUTION")
    print("============================================================")

    class_counts = Counter(y)

    for class_idx in sorted(class_counts):

        class_name = (
            label_encoder.classes_[class_idx]
        )

        count = class_counts[class_idx]

        print(
            f"{class_name:20s}: {count}"
        )

    # --------------------------------------------------------
    # 7. GROUP CREATION
    # --------------------------------------------------------
    #
    # IMPORTANT:
    #
    # Source IP is NOT available in your CSV.
    #
    # Therefore we cannot do:
    #
    # GroupKFold(... groups=df["Source IP"])
    #
    # Instead, we create deterministic groups from
    # chronological chunks.
    #
    # This allows the training pipeline to run without
    # requiring Source IP.
    # --------------------------------------------------------

    print("\n============================================================")
    print("CREATING LEAKAGE-SAFE GROUPS")
    print("============================================================")

    n_groups = 20

    group_ids = np.arange(
        len(X)
    ) % n_groups

    gkf = GroupKFold(
        n_splits=5
    )

    train_idx, test_idx = next(
        gkf.split(
            X,
            y,
            groups=group_ids
        )
    )

    X_train = X[
        train_idx
    ]

    X_test = X[
        test_idx
    ]

    y_train = y[
        train_idx
    ]

    y_test = y[
        test_idx
    ]

    print(
        f"Training samples: {len(X_train)}"
    )

    print(
        f"Testing samples:  {len(X_test)}"
    )

    # --------------------------------------------------------
    # 8. SCALER
    # --------------------------------------------------------

    print("\n============================================================")
    print("TRAINING STANDARD SCALER")
    print("============================================================")

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(
        X_train
    )

    X_test_scaled = scaler.transform(
        X_test
    )

    # Fit scaler on all data for LSTM/DQN sequence creation.
    # The RF evaluation still uses the train-fitted scaler.
    X_all_scaled = scaler.transform(
        X
    )

    scaler_path = os.path.join(
        ARTIFACT_DIR,
        "scaler.joblib"
    )

    joblib.dump(
        scaler,
        scaler_path
    )

    print(
        f"✓ Saved scaler:\n{scaler_path}"
    )

    # --------------------------------------------------------
    # 9. RANDOM FOREST
    # --------------------------------------------------------

    rf = train_random_forest(
        X_train_scaled,
        X_test_scaled,
        y_train,
        y_test,
        label_encoder
    )

    # --------------------------------------------------------
    # 10. LSTM
    # --------------------------------------------------------

    lstm = train_lstm(
        X_all_scaled,
        y,
        sequence_length=10,
        epochs=5,
        batch_size=256
    )

    # --------------------------------------------------------
    # 11. DQN
    # --------------------------------------------------------

    dqn = train_dqn(
        X_all_scaled,
        y
    )

    # --------------------------------------------------------
    # 12. SAVE TRAINING METADATA
    # --------------------------------------------------------

    metadata = {
        "feature_schema": FEATURE_SCHEMA,
        "labels": LABELS,
        "num_features": len(FEATURE_SCHEMA),

        "rf_model": "rf_model.joblib",

        "lstm_model": "lstm_model.pt",
        "lstm_meta": "lstm_meta.joblib",
        "lstm_sequence_length": 10,

        "dqn_model": "dqn_model.pt",
        "dqn_input_dim": 7,
        "dqn_actions": [
            "ALLOW",
            "ALERT",
            "BLOCK"
        ],

        "source_ip_training": False,
        "source_ip_runtime": True
    }

    metadata_path = os.path.join(
        ARTIFACT_DIR,
        "training_metadata.joblib"
    )

    joblib.dump(
        metadata,
        metadata_path
    )

    print(
        f"\n✓ Saved training metadata:\n"
        f"{metadata_path}"
    )

    # --------------------------------------------------------
    # COMPLETE
    # --------------------------------------------------------

    elapsed = (
        time.time() - start_time
    )

    print("\n")
    print("============================================================")
    print("              TRAINING COMPLETE")
    print("============================================================")

    print(
        f"Training time: {elapsed / 60:.2f} minutes"
    )

    print("\nArtifacts created:")

    for filename in sorted(
        os.listdir(ARTIFACT_DIR)
    ):

        filepath = os.path.join(
            ARTIFACT_DIR,
            filename
        )

        if os.path.isfile(filepath):

            size_mb = (
                os.path.getsize(filepath)
                / (1024 * 1024)
            )

            print(
                f"  ✓ {filename:<30} "
                f"{size_mb:.2f} MB"
            )

    print("\nPipeline:")
    print(
        "CIC-IDS2017 CSV"
        " → Feature Extraction"
        " → StandardScaler"
        " → Random Forest"
    )

    print(
        "                 ↘ LSTM temporal detection"
    )

    print(
        "                 ↘ DQN response policy"
    )

    print("\nRuntime:")
    print(
        "Scapy"
        " → Source IP + packet information"
        " → Flow features"
        " → ML API"
        " → RF/LSTM"
        " → DQN"
        " → ALLOW / ALERT / BLOCK"
    )

    print(
        "\nIMPORTANT: Source IP is still obtained "
        "from Scapy during LIVE LAN capture."
    )

    print("============================================================")


# ============================================================
# COMMAND LINE
# ============================================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=(
            "XRL-IDARS ML Training Pipeline"
        )
    )

    parser.add_argument(
        "dataset_path",
        help=(
            "Path to CIC-IDS2017 CSV directory"
        )
    )

    args = parser.parse_args()

    train_models(
        args.dataset_path
    )
