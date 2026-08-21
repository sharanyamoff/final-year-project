import os
import sys
import time
import random
import warnings
from collections import Counter

import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    confusion_matrix
)

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader


warnings.filterwarnings("ignore")


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.append(BASE_DIR)

from models.feature_schema import FEATURE_SCHEMA, LABELS
from models.lstm_model import TemporalLSTM
from models.dqn_model import DQN


ARTIFACT_DIR = os.path.join(
    BASE_DIR,
    "artifacts"
)


# ============================================================
# REPRODUCIBILITY
# ============================================================

SEED = 42

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)


# ============================================================
# CONFIGURATION
# ============================================================

LSTM_TIMESTEPS = 5
LSTM_HIDDEN_DIM = 64
LSTM_NUM_LAYERS = 2

LSTM_EPOCHS = 5
LSTM_BATCH_SIZE = 256
LSTM_LEARNING_RATE = 0.001


DQN_INPUT_DIM = 7
DQN_HIDDEN_DIM = 32
DQN_ACTIONS = 3

DQN_EPOCHS = 10
DQN_BATCH_SIZE = 256
DQN_LEARNING_RATE = 0.001


# ============================================================
# ARTIFACT DIRECTORY
# ============================================================

def create_artifact_dir():

    os.makedirs(
        ARTIFACT_DIR,
        exist_ok=True
    )

    print(
        f"Artifact directory: {ARTIFACT_DIR}"
    )


# ============================================================
# LABEL MAPPING
# ============================================================

def map_label(label):

    if pd.isna(label):
        return "BENIGN"

    label = str(label).strip()

    if label == "BENIGN":
        return "BENIGN"

    # --------------------------------------------------------
    # DoS / DDoS
    # --------------------------------------------------------

    if label in [
        "DDoS",
        "DoS Hulk",
        "DoS GoldenEye",
        "DoS slowloris",
        "DoS Slowhttptest"
    ]:
        return "DOS_ATTACK"

    # --------------------------------------------------------
    # Port Scan
    # --------------------------------------------------------

    if label == "PortScan":
        return "PORT_SCAN"

    # --------------------------------------------------------
    # Brute Force
    # --------------------------------------------------------

    if label in [
        "FTP-Patator",
        "SSH-Patator"
    ]:
        return "BRUTE_FORCE"

    # --------------------------------------------------------
    # Botnet
    # --------------------------------------------------------

    if label == "Bot":
        return "BOTNET"

    # --------------------------------------------------------
    # Infiltration
    # --------------------------------------------------------

    if label == "Infiltration":
        return "INFILTRATION"

    # --------------------------------------------------------
    # Web attacks
    # --------------------------------------------------------

    if (
        "Web Attack" in label
        or label == "Heartbleed"
    ):
        return "WEB_ATTACK"

    # Unknown labels -> benign
    return "BENIGN"


# ============================================================
# LOAD CIC-IDS2017 CSV FILES
#
# IMPORTANT:
# CIC-IDS2017 CSVs do NOT provide Source IP.
# CIC-IDS2017 CSVs in this project may also NOT provide Timestamp.
#
# Therefore:
#   Source IP  -> NOT required during training
#   Timestamp  -> NOT required during training
#
# Source IP is obtained later from Scapy during LIVE LAN capture.
# ============================================================

def load_and_clean_data(dataset_path):

    print()
    print("=" * 70)
    print("LOADING CIC-IDS2017 DATASET")
    print("=" * 70)

    print(
        f"Dataset path: {dataset_path}"
    )

    if not os.path.exists(dataset_path):

        raise FileNotFoundError(
            f"Dataset directory does not exist: {dataset_path}"
        )

    files = sorted(
        [
            f
            for f in os.listdir(dataset_path)
            if f.lower().endswith(".csv")
        ]
    )

    if not files:

        raise FileNotFoundError(
            f"No CSV files found in {dataset_path}"
        )

    print(
        f"Found {len(files)} CSV files."
    )

    dfs = []

    for filename in files:

        filepath = os.path.join(
            dataset_path,
            filename
        )

        print()
        print(
            f"Reading: {filename}"
        )

        try:

            df = pd.read_csv(
                filepath,
                encoding="cp1252",
                low_memory=False
            )

            # ------------------------------------------------
            # Clean column names
            # ------------------------------------------------

            df.columns = (
                df.columns
                .astype(str)
                .str.replace("\ufeff", "", regex=False)
                .str.strip()
            )

            print(
                f"Rows: {len(df)}"
            )

            print(
                f"Columns: {len(df.columns)}"
            )

            # ------------------------------------------------
            # Label must exist
            # ------------------------------------------------

            if "Label" not in df.columns:

                print(
                    "WARNING: Label column missing."
                )

                print(
                    "Skipping this file."
                )

                continue

            # ------------------------------------------------
            # IMPORTANT
            #
            # Source IP is intentionally NOT required.
            # Timestamp is intentionally NOT required.
            # ------------------------------------------------

            if "Source IP" not in df.columns:

                print(
                    "Source IP: not present "
                    "(EXPECTED for CIC-IDS2017)"
                )

            else:

                print(
                    "Source IP: present"
                )

            if "Timestamp" not in df.columns:

                print(
                    "Timestamp: not present "
                    "(OK - not required)"
                )

            else:

                print(
                    "Timestamp: present"
                )

            # ------------------------------------------------
            # Store filename for temporal grouping.
            #
            # This is NOT a model feature.
            # ------------------------------------------------

            df["_dataset_file"] = filename

            # Preserve order inside each CSV
            df["_row_order"] = np.arange(
                len(df),
                dtype=np.int64
            )

            dfs.append(df)

        except Exception as e:

            print(
                f"WARNING: Could not read {filename}"
            )

            print(
                f"Reason: {e}"
            )

    if not dfs:

        raise RuntimeError(
            "No usable CIC-IDS2017 CSV files were found."
        )

    df = pd.concat(
        dfs,
        ignore_index=True
    )

    print()
    print(
        f"Combined rows: {len(df)}"
    )

    # --------------------------------------------------------
    # Replace infinity
    # --------------------------------------------------------

    df = df.replace(
        [np.inf, -np.inf],
        np.nan
    )

    return df


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(df):

    print()
    print("=" * 70)
    print("EXTRACTING FEATURES")
    print("=" * 70)

    # --------------------------------------------------------
    # CIC-IDS2017 columns required for our model
    # --------------------------------------------------------

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
        "Label"
    ]

    missing = [
        col
        for col in required_columns
        if col not in df.columns
    ]

    if missing:

        raise ValueError(
            "Required CIC-IDS2017 columns are missing:\n"
            + "\n".join(
                f"  - {col}"
                for col in missing
            )
        )

    out = pd.DataFrame(
        index=df.index
    )

    # --------------------------------------------------------
    # Convert numerical columns
    # --------------------------------------------------------

    numeric_columns = [
        "Flow Duration",
        "Flow Packets/s",
        "Flow Bytes/s",
        "Packet Length Mean",
        "Packet Length Std",
        "SYN Flag Count",
        "ACK Flag Count",
        "RST Flag Count",
        "FIN Flag Count"
    ]

    for col in numeric_columns:

        df[col] = pd.to_numeric(
            df[col],
            errors="coerce"
        )

    # --------------------------------------------------------
    # Feature 1
    # --------------------------------------------------------

    out["flow_duration_ms"] = (
        df["Flow Duration"] / 1000.0
    )

    # --------------------------------------------------------
    # Feature 2
    # --------------------------------------------------------

    out["flow_packets_per_s"] = (
        df["Flow Packets/s"]
    )

    # --------------------------------------------------------
    # Feature 3
    # --------------------------------------------------------

    out["flow_bytes_per_s"] = (
        df["Flow Bytes/s"]
    )

    # --------------------------------------------------------
    # Feature 4
    # --------------------------------------------------------

    out["packet_length_mean"] = (
        df["Packet Length Mean"]
    )

    # --------------------------------------------------------
    # Feature 5
    # --------------------------------------------------------

    out["packet_length_std"] = (
        df["Packet Length Std"]
    )

    # --------------------------------------------------------
    # Feature 6
    # --------------------------------------------------------

    out["syn_count"] = (
        df["SYN Flag Count"]
    )

    # --------------------------------------------------------
    # Feature 7
    # --------------------------------------------------------

    out["ack_count"] = (
        df["ACK Flag Count"]
    )

    # --------------------------------------------------------
    # Feature 8
    # --------------------------------------------------------

    out["rst_count"] = (
        df["RST Flag Count"]
    )

    # --------------------------------------------------------
    # Feature 9
    # --------------------------------------------------------

    out["fin_count"] = (
        df["FIN Flag Count"]
    )

    # --------------------------------------------------------
    # Feature 10
    #
    # Avoid division by zero
    # --------------------------------------------------------

    out["syn_ack_ratio"] = (
        df["SYN Flag Count"]
        /
        df["ACK Flag Count"].clip(
            lower=1
        )
    )

    # --------------------------------------------------------
    # Label
    # --------------------------------------------------------

    out["Label"] = (
        df["Label"]
        .astype(str)
        .str.strip()
        .apply(map_label)
    )

    # --------------------------------------------------------
    # Internal dataset information
    #
    # These are NOT ML features.
    # They are only used to build LSTM sequences without
    # needing Source IP or Timestamp.
    # --------------------------------------------------------

    if "_dataset_file" in df.columns:

        out["_dataset_file"] = (
            df["_dataset_file"].values
        )

    else:

        out["_dataset_file"] = "dataset"

    if "_row_order" in df.columns:

        out["_row_order"] = (
            df["_row_order"].values
        )

    else:

        out["_row_order"] = np.arange(
            len(out)
        )

    # --------------------------------------------------------
    # Clean
    # --------------------------------------------------------

    out = out.replace(
        [np.inf, -np.inf],
        np.nan
    )

    out = out.dropna(
        subset=FEATURE_SCHEMA + ["Label"]
    )

    # --------------------------------------------------------
    # Verify feature schema
    # --------------------------------------------------------

    missing_features = [
        feature
        for feature in FEATURE_SCHEMA
        if feature not in out.columns
    ]

    if missing_features:

        raise ValueError(
            "Project feature schema mismatch.\n"
            "Missing features:\n"
            + "\n".join(
                f"  - {feature}"
                for feature in missing_features
            )
        )

    print()
    print(
        f"Rows remaining after cleaning: {len(out)}"
    )

    print()
    print("Model Features:")

    for feature in FEATURE_SCHEMA:

        print(
            f"  ✓ {feature}"
        )

    print()
    print("Mapped Classes:")

    print(
        out["Label"]
        .value_counts()
        .to_string()
    )

    return out


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

def train_random_forest(
    df,
    scaler
):

    print()
    print("=" * 70)
    print("TRAINING RANDOM FOREST")
    print("=" * 70)

    # --------------------------------------------------------
    # X
    # --------------------------------------------------------

    X = df[
        FEATURE_SCHEMA
    ].values.astype(
        np.float32
    )

    # --------------------------------------------------------
    # Label encoder
    # --------------------------------------------------------

    label_encoder = LabelEncoder()

    label_encoder.fit(
        LABELS
    )

    y = label_encoder.transform(
        df["Label"]
    )

    # --------------------------------------------------------
    # Class distribution
    # --------------------------------------------------------

    print()
    print("Class Distribution:")

    counts = Counter(y)

    for idx in range(
        len(label_encoder.classes_)
    ):

        count = counts.get(
            idx,
            0
        )

        print(
            f"  {label_encoder.classes_[idx]:<20} "
            f"{count}"
        )

    # --------------------------------------------------------
    # Make sure every class exists
    # --------------------------------------------------------

    missing_classes = [
        label
        for label in LABELS
        if label not in set(
            df["Label"]
        )
    ]

    if missing_classes:

        print()
        print(
            "WARNING: The following classes "
            "are not present in this dataset:"
        )

        for label in missing_classes:

            print(
                f"  - {label}"
            )

    # --------------------------------------------------------
    # Train / test split
    #
    # We do NOT use Source IP.
    # --------------------------------------------------------

    print()
    print(
        "Creating train/test split..."
    )

    try:

        X_train, X_test, y_train, y_test = (
            train_test_split(
                X,
                y,
                test_size=0.20,
                random_state=SEED,
                stratify=y
            )
        )

    except ValueError as e:

        print()
        print(
            "WARNING: Stratified split failed."
        )

        print(
            f"Reason: {e}"
        )

        print(
            "Using regular random split."
        )

        X_train, X_test, y_train, y_test = (
            train_test_split(
                X,
                y,
                test_size=0.20,
                random_state=SEED
            )
        )

    print(
        f"Training samples: {len(X_train)}"
    )

    print(
        f"Testing samples : {len(X_test)}"
    )

    # --------------------------------------------------------
    # Fit scaler ONLY on training data
    # --------------------------------------------------------

    print()
    print(
        "Fitting StandardScaler..."
    )

    X_train_scaled = scaler.fit_transform(
        X_train
    )

    X_test_scaled = scaler.transform(
        X_test
    )

    # --------------------------------------------------------
    # Random Forest
    # --------------------------------------------------------

    print()
    print(
        "Fitting Random Forest..."
    )

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=SEED,
        n_jobs=-1
    )

    rf.fit(
        X_train_scaled,
        y_train
    )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    predictions = rf.predict(
        X_test_scaled
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print()
    print(
        f"Random Forest Accuracy: "
        f"{accuracy * 100:.2f}%"
    )

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    print()
    print(
        "Classification Report:"
    )

    print(
        classification_report(
            y_test,
            predictions,
            labels=np.arange(
                len(label_encoder.classes_)
            ),
            target_names=label_encoder.classes_,
            zero_division=0
        )
    )

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    cm = confusion_matrix(
        y_test,
        predictions,
        labels=np.arange(
            len(label_encoder.classes_)
        )
    )

    print(
        "Confusion Matrix:"
    )

    print(cm)

    # --------------------------------------------------------
    # Save RF artifact
    # --------------------------------------------------------

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

    print()
    print(
        f"✓ Saved: {rf_path}"
    )

    return (
        rf,
        label_encoder,
        X_train,
        X_test,
        y_train,
        y_test,
        accuracy
    )


# ============================================================
# CREATE LSTM SEQUENCES
#
# IMPORTANT:
# We do NOT group by Source IP.
#
# Instead, sequences are created separately inside each
# CIC-IDS2017 CSV file.
#
# This prevents sequences from crossing between unrelated
# CSV files.
# ============================================================

def create_lstm_sequences(
    df,
    scaler,
    label_encoder,
    timesteps=5
):

    sequences = []
    targets = []

    benign_index = label_encoder.transform(
        ["BENIGN"]
    )[0]

    # --------------------------------------------------------
    # Process each original CSV separately
    # --------------------------------------------------------

    for filename, group in df.groupby(
        "_dataset_file",
        sort=False
    ):

        group = group.sort_values(
            "_row_order"
        )

        X = group[
            FEATURE_SCHEMA
        ].values.astype(
            np.float32
        )

        labels = label_encoder.transform(
            group["Label"]
        )

        if len(X) < timesteps:

            continue

        X_scaled = scaler.transform(
            X
        )

        # ----------------------------------------------------
        # Sliding windows
        # ----------------------------------------------------

        for i in range(
            len(X_scaled) - timesteps + 1
        ):

            sequence = X_scaled[
                i:i + timesteps
            ]

            window_labels = labels[
                i:i + timesteps
            ]

            # Binary temporal target:
            #
            # BENIGN = 0
            # ANY ATTACK = 1
            #
            is_anomaly = (
                np.any(
                    window_labels
                    != benign_index
                )
            )

            sequences.append(
                sequence
            )

            targets.append(
                float(is_anomaly)
            )

    if not sequences:

        return (
            np.empty(
                (
                    0,
                    timesteps,
                    len(FEATURE_SCHEMA)
                ),
                dtype=np.float32
            ),
            np.empty(
                (0,),
                dtype=np.float32
            )
        )

    return (
        np.asarray(
            sequences,
            dtype=np.float32
        ),
        np.asarray(
            targets,
            dtype=np.float32
        )
    )


# ============================================================
# TRAIN LSTM
# ============================================================

def train_lstm(
    df,
    scaler,
    label_encoder
):

    print()
    print("=" * 70)
    print("TRAINING TEMPORAL LSTM")
    print("=" * 70)

    X_seq, y_seq = create_lstm_sequences(
        df,
        scaler,
        label_encoder,
        timesteps=LSTM_TIMESTEPS
    )

    print()
    print(
        f"LSTM sequences: {len(X_seq)}"
    )

    if len(X_seq) == 0:

        raise RuntimeError(
            "Not enough data to create LSTM sequences."
        )

    print(
        f"Sequence shape: {X_seq.shape}"
    )

    # --------------------------------------------------------
    # Dataset
    # --------------------------------------------------------

    X_tensor = torch.tensor(
        X_seq,
        dtype=torch.float32
    )

    y_tensor = torch.tensor(
        y_seq.reshape(-1, 1),
        dtype=torch.float32
    )

    dataset = TensorDataset(
        X_tensor,
        y_tensor
    )

    loader = DataLoader(
        dataset,
        batch_size=LSTM_BATCH_SIZE,
        shuffle=True
    )

    # --------------------------------------------------------
    # Model
    # --------------------------------------------------------

    model = TemporalLSTM(
        input_dim=len(
            FEATURE_SCHEMA
        ),
        hidden_dim=LSTM_HIDDEN_DIM,
        num_layers=LSTM_NUM_LAYERS
    )

    criterion = nn.BCELoss()

    optimizer = optim.Adam(
        model.parameters(),
        lr=LSTM_LEARNING_RATE
    )

    # --------------------------------------------------------
    # Training
    # --------------------------------------------------------

    model.train()

    final_loss = 0.0

    for epoch in range(
        LSTM_EPOCHS
    ):

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

            total_loss += (
                loss.item()
                *
                len(batch_x)
            )

        final_loss = (
            total_loss
            /
            len(dataset)
        )

        print(
            f"Epoch "
            f"{epoch + 1}/{LSTM_EPOCHS} "
            f"- Loss: {final_loss:.6f}"
        )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    model_path = os.path.join(
        ARTIFACT_DIR,
        "lstm_model.pt"
    )

    torch.save(
        model.state_dict(),
        model_path
    )

    # --------------------------------------------------------
    # Save LSTM metadata
    # --------------------------------------------------------

    meta = {
        "input_dim": len(
            FEATURE_SCHEMA
        ),
        "hidden_dim": LSTM_HIDDEN_DIM,
        "num_layers": LSTM_NUM_LAYERS,
        "timesteps": LSTM_TIMESTEPS,
        "features": FEATURE_SCHEMA,
        "target_type": "binary_anomaly",
        "target_definition": {
            "BENIGN": 0,
            "ANY_ATTACK": 1
        }
    }

    meta_path = os.path.join(
        ARTIFACT_DIR,
        "lstm_meta.joblib"
    )

    joblib.dump(
        meta,
        meta_path
    )

    print()
    print(
        f"✓ Saved: {model_path}"
    )

    print(
        f"✓ Saved: {meta_path}"
    )

    return (
        model,
        final_loss
    )


# ============================================================
# CREATE DQN DATASET
# ============================================================

def create_dqn_dataset(
    df,
    rf,
    scaler,
    label_encoder
):

    print()
    print("=" * 70)
    print("CREATING DQN TRAINING DATA")
    print("=" * 70)

    X = df[
        FEATURE_SCHEMA
    ].values.astype(
        np.float32
    )

    X_scaled = scaler.transform(
        X
    )

    labels = label_encoder.transform(
        df["Label"]
    )

    # --------------------------------------------------------
    # RF probabilities
    # --------------------------------------------------------

    rf_probs = rf.predict_proba(
        X_scaled
    )

    max_rf_prob = np.max(
        rf_probs,
        axis=1
    )

    # --------------------------------------------------------
    # Anomaly flag
    # --------------------------------------------------------

    benign_index = label_encoder.transform(
        ["BENIGN"]
    )[0]

    anomaly = (
        labels != benign_index
    ).astype(
        np.float32
    )

    # --------------------------------------------------------
    # Packet rate
    # --------------------------------------------------------

    packets_per_s = (
        df["flow_packets_per_s"]
        .values.astype(
            np.float32
        )
    )

    # --------------------------------------------------------
    # SYN count
    # --------------------------------------------------------

    syn_count = (
        df["syn_count"]
        .values.astype(
            np.float32
        )
    )

    # --------------------------------------------------------
    # Normalize packet rate
    # --------------------------------------------------------

    packet_norm = np.clip(
        packets_per_s / 10000.0,
        0.0,
        1.0
    )

    # --------------------------------------------------------
    # Normalize SYN count
    # --------------------------------------------------------

    syn_norm = np.clip(
        syn_count / 100.0,
        0.0,
        1.0
    )

    # --------------------------------------------------------
    # Temporal/anomaly score
    # --------------------------------------------------------

    lstm_score = (
        0.7 * anomaly
        +
        0.3 * packet_norm
    )

    lstm_score = np.clip(
        lstm_score,
        0.0,
        1.0
    )

    # --------------------------------------------------------
    # Risk score
    # --------------------------------------------------------

    risk_score = (
        0.6 * max_rf_prob
        +
        0.4 * lstm_score
    )

    risk_score = np.clip(
        risk_score,
        0.0,
        1.0
    )

    # --------------------------------------------------------
    # Historical incident count
    # --------------------------------------------------------

    historical = np.zeros(
        len(df),
        dtype=np.float32
    )

    running_incidents = 0

    for i in range(
        len(df)
    ):

        historical[i] = min(
            running_incidents / 100.0,
            1.0
        )

        if anomaly[i] > 0:

            running_incidents += 1

    # --------------------------------------------------------
    # Blocked state
    #
    # Initial training state = 0
    # --------------------------------------------------------

    blocked = np.zeros(
        len(df),
        dtype=np.float32
    )

    # --------------------------------------------------------
    # DQN STATE
    #
    # 0 RF confidence
    # 1 LSTM/anomaly score
    # 2 risk score
    # 3 packet rate
    # 4 SYN count
    # 5 historical incidents
    # 6 blocked state
    # --------------------------------------------------------

    states = np.column_stack(
        [
            max_rf_prob,
            lstm_score,
            risk_score,
            packet_norm,
            syn_norm,
            historical,
            blocked
        ]
    ).astype(
        np.float32
    )

    # --------------------------------------------------------
    # ACTIONS
    #
    # 0 = ALLOW
    # 1 = ALERT
    # 2 = BLOCK
    # --------------------------------------------------------

    actions = np.zeros(
        len(risk_score),
        dtype=np.int64
    )

    actions[
        risk_score >= 0.40
    ] = 1

    actions[
        risk_score >= 0.65
    ] = 2

    # --------------------------------------------------------
    # Q targets
    # --------------------------------------------------------

    q_targets = np.zeros(
        (
            len(states),
            DQN_ACTIONS
        ),
        dtype=np.float32
    )

    for i, action in enumerate(
        actions
    ):

        risk = risk_score[i]

        # Base values
        q_targets[i, 0] = (
            1.0 - risk
        )

        q_targets[i, 1] = 0.5

        q_targets[i, 2] = risk

        # Reward selected action
        if action == 0:

            q_targets[i, 0] += 0.5

        elif action == 1:

            q_targets[i, 1] += 0.5

        else:

            q_targets[i, 2] += 0.5

    return (
        states,
        q_targets
    )


# ============================================================
# TRAIN DQN
# ============================================================

def train_dqn(
    df,
    rf,
    scaler,
    label_encoder
):

    print()
    print("=" * 70)
    print("TRAINING DQN")
    print("=" * 70)

    states, q_targets = create_dqn_dataset(
        df,
        rf,
        scaler,
        label_encoder
    )

    print()
    print(
        f"DQN training samples: {len(states)}"
    )

    # --------------------------------------------------------
    # Tensor dataset
    # --------------------------------------------------------

    X_tensor = torch.tensor(
        states,
        dtype=torch.float32
    )

    y_tensor = torch.tensor(
        q_targets,
        dtype=torch.float32
    )

    dataset = TensorDataset(
        X_tensor,
        y_tensor
    )

    loader = DataLoader(
        dataset,
        batch_size=DQN_BATCH_SIZE,
        shuffle=True
    )

    # --------------------------------------------------------
    # DQN model
    # --------------------------------------------------------

    model = DQN(
        input_dim=DQN_INPUT_DIM,
        hidden_dim=DQN_HIDDEN_DIM,
        num_actions=DQN_ACTIONS
    )

    criterion = nn.MSELoss()

    optimizer = optim.Adam(
        model.parameters(),
        lr=DQN_LEARNING_RATE
    )

    # --------------------------------------------------------
    # Training
    # --------------------------------------------------------

    model.train()

    final_loss = 0.0

    for epoch in range(
        DQN_EPOCHS
    ):

        total_loss = 0.0

        for batch_x, batch_y in loader:

            optimizer.zero_grad()

            predictions = model(
                batch_x
            )

            loss = criterion(
                predictions,
                batch_y
            )

            loss.backward()

            optimizer.step()

            total_loss += (
                loss.item()
                *
                len(batch_x)
            )

        final_loss = (
            total_loss
            /
            len(dataset)
        )

        print(
            f"Epoch "
            f"{epoch + 1}/{DQN_EPOCHS} "
            f"- Loss: {final_loss:.6f}"
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

    print()
    print(
        f"✓ Saved: {dqn_path}"
    )

    return (
        model,
        final_loss
    )


# ============================================================
# SAVE SCALER
# ============================================================

def save_scaler(
    scaler
):

    scaler_path = os.path.join(
        ARTIFACT_DIR,
        "scaler.joblib"
    )

    joblib.dump(
        scaler,
        scaler_path
    )

    print(
        f"✓ Saved: {scaler_path}"
    )


# ============================================================
# SAVE LABEL ENCODER
# ============================================================

def save_label_encoder(
    label_encoder
):

    path = os.path.join(
        ARTIFACT_DIR,
        "label_encoder.joblib"
    )

    joblib.dump(
        label_encoder,
        path
    )

    print(
        f"✓ Saved: {path}"
    )


# ============================================================
# SAVE SHAP BACKGROUND
# ============================================================

def save_shap_background(
    X_train_scaled
):

    if len(X_train_scaled) == 0:

        return

    sample_size = min(
        200,
        len(X_train_scaled)
    )

    rng = np.random.default_rng(
        SEED
    )

    indices = rng.choice(
        len(X_train_scaled),
        size=sample_size,
        replace=False
    )

    background = (
        X_train_scaled[
            indices
        ]
    )

    path = os.path.join(
        ARTIFACT_DIR,
        "shap_background.joblib"
    )

    joblib.dump(
        background,
        path
    )

    print(
        f"✓ Saved: {path}"
    )


# ============================================================
# SAVE METADATA
# ============================================================

def save_metadata(
    df,
    rf_accuracy,
    lstm_loss,
    dqn_loss,
    start_time
):

    metadata = {

        "status": "TRAINED",

        "project": "XRL-IDARS",

        "dataset": "CIC-IDS2017",

        "feature_schema": FEATURE_SCHEMA,

        "labels": LABELS,

        "num_features": len(
            FEATURE_SCHEMA
        ),

        "num_classes": len(
            LABELS
        ),

        # ----------------------------------------------------
        # IMPORTANT ARCHITECTURE INFORMATION
        # ----------------------------------------------------

        "source_ip_used_in_training": False,

        "timestamp_required_in_training": False,

        "live_source_ip_provider": "Scapy",

        "training_sequence_group": "CSV_FILENAME",

        # ----------------------------------------------------
        # Random Forest
        # ----------------------------------------------------

        "random_forest": {

            "n_estimators": 200,

            "accuracy": rf_accuracy
        },

        # ----------------------------------------------------
        # LSTM
        # ----------------------------------------------------

        "lstm": {

            "timesteps": LSTM_TIMESTEPS,

            "input_dim": len(
                FEATURE_SCHEMA
            ),

            "hidden_dim": LSTM_HIDDEN_DIM,

            "num_layers": LSTM_NUM_LAYERS,

            "target_type": "binary",

            "target_definition": {
                "BENIGN": 0,
                "ANY_ATTACK": 1
            },

            "loss": lstm_loss
        },

        # ----------------------------------------------------
        # DQN
        # ----------------------------------------------------

        "dqn": {

            "input_dim": DQN_INPUT_DIM,

            "hidden_dim": DQN_HIDDEN_DIM,

            "num_actions": DQN_ACTIONS,

            "actions": [
                "ALLOW",
                "ALERT",
                "BLOCK"
            ],

            "loss": dqn_loss
        },

        # ----------------------------------------------------
        # Dataset
        # ----------------------------------------------------

        "training_rows": len(df),

        "training_time_seconds": (
            time.time()
            -
            start_time
        )
    }

    metadata_path = os.path.join(
        ARTIFACT_DIR,
        "metadata.joblib"
    )

    joblib.dump(
        metadata,
        metadata_path
    )

    print(
        f"✓ Saved: {metadata_path}"
    )


# ============================================================
# ARTIFACT CHECK
# ============================================================

def check_artifacts():

    print()
    print("=" * 70)
    print("CHECKING GENERATED ARTIFACTS")
    print("=" * 70)

    required_artifacts = [

        "rf_model.joblib",

        "scaler.joblib",

        "label_encoder.joblib",

        "shap_background.joblib",

        "lstm_model.pt",

        "lstm_meta.joblib",

        "dqn_model.pt",

        "metadata.joblib"
    ]

    all_ok = True

    for filename in required_artifacts:

        path = os.path.join(
            ARTIFACT_DIR,
            filename
        )

        if os.path.exists(path):

            size_mb = (
                os.path.getsize(path)
                /
                (1024 * 1024)
            )

            print(
                f"✓ {filename:<28} "
                f"{size_mb:.2f} MB"
            )

        else:

            print(
                f"✗ MISSING: {filename}"
            )

            all_ok = False

    return all_ok


# ============================================================
# MAIN TRAINING PIPELINE
# ============================================================

def train_models(
    data_path
):

    start_time = time.time()

    print()
    print("=" * 70)
    print("XRL-IDARS COMPLETE TRAINING PIPELINE")
    print("=" * 70)

    print(
        f"Dataset: {data_path}"
    )

    print(
        f"Artifacts: {ARTIFACT_DIR}"
    )

    print()
    print(
        "TRAINING DESIGN:"
    )

    print(
        "  Source IP during training : NOT REQUIRED"
    )

    print(
        "  Timestamp during training  : NOT REQUIRED"
    )

    print(
        "  Source IP during LIVE LAN : Scapy"
    )

    print(
        "  LSTM grouping              : CSV file"
    )

    # --------------------------------------------------------
    # 1. Artifact directory
    # --------------------------------------------------------

    create_artifact_dir()

    # --------------------------------------------------------
    # 2. Load dataset
    # --------------------------------------------------------

    raw_df = load_and_clean_data(
        data_path
    )

    # --------------------------------------------------------
    # 3. Extract features
    # --------------------------------------------------------

    df = extract_features(
        raw_df
    )

    # --------------------------------------------------------
    # 4. Verify dataset
    # --------------------------------------------------------

    if len(df) == 0:

        raise RuntimeError(
            "No rows remain after feature extraction."
        )

    print()
    print(
        f"Final training rows: {len(df)}"
    )

    # --------------------------------------------------------
    # 5. Scaler
    # --------------------------------------------------------

    scaler = StandardScaler()

    # --------------------------------------------------------
    # 6. Random Forest
    # --------------------------------------------------------

    (
        rf,
        label_encoder,
        X_train,
        X_test,
        y_train,
        y_test,
        rf_accuracy
    ) = train_random_forest(
        df,
        scaler
    )

    # --------------------------------------------------------
    # 7. Save scaler
    # --------------------------------------------------------

    save_scaler(
        scaler
    )

    # --------------------------------------------------------
    # 8. Save label encoder
    # --------------------------------------------------------

    save_label_encoder(
        label_encoder
    )

    # --------------------------------------------------------
    # 9. SHAP background
    # --------------------------------------------------------

    X_train_scaled = scaler.transform(
        X_train
    )

    save_shap_background(
        X_train_scaled
    )

    # --------------------------------------------------------
    # 10. LSTM
    # --------------------------------------------------------

    (
        lstm_model,
        lstm_loss
    ) = train_lstm(
        df,
        scaler,
        label_encoder
    )

    # --------------------------------------------------------
    # 11. DQN
    # --------------------------------------------------------

    (
        dqn_model,
        dqn_loss
    ) = train_dqn(
        df,
        rf,
        scaler,
        label_encoder
    )

    # --------------------------------------------------------
    # 12. Metadata
    # --------------------------------------------------------

    save_metadata(
        df,
        rf_accuracy,
        lstm_loss,
        dqn_loss,
        start_time
    )

    # --------------------------------------------------------
    # 13. Artifact check
    # --------------------------------------------------------

    all_ok = check_artifacts()

    # --------------------------------------------------------
    # 14. Final summary
    # --------------------------------------------------------

    total_time = (
        time.time()
        -
        start_time
    )

    print()
    print("=" * 70)
    print("TRAINING SUMMARY")
    print("=" * 70)

    print()
    print(
        f"Total rows       : {len(df)}"
    )

    print(
        f"Training rows    : {len(X_train)}"
    )

    print(
        f"Testing rows     : {len(X_test)}"
    )

    print(
        f"RF Accuracy      : "
        f"{rf_accuracy * 100:.2f}%"
    )

    print(
        f"LSTM Final Loss  : "
        f"{lstm_loss:.6f}"
    )

    print(
        f"DQN Final Loss   : "
        f"{dqn_loss:.6f}"
    )

    print()
    print(
        "Features:"
    )

    for feature in FEATURE_SCHEMA:

        print(
            f"  - {feature}"
        )

    print()
    print(
        "Labels:"
    )

    for label in LABELS:

        print(
            f"  - {label}"
        )

    print()
    print(
        "Source IP training dependency : NO"
    )

    print(
        "Timestamp training dependency  : NO"
    )

    print(
        "Live Source IP                 : Scapy"
    )

    print(
        "LSTM sequence grouping        : CSV file"
    )

    print()
    print(
        f"Total training time: "
        f"{total_time:.2f} seconds"
    )

    print()

    if all_ok:

        print(
            "✓ ALL REQUIRED ARTIFACTS CREATED"
        )

        print(
            "✓ TRAINING COMPLETED SUCCESSFULLY"
        )

    else:

        print(
            "WARNING: SOME ARTIFACTS ARE MISSING"
        )

    print(
        "=" * 70
    )


# ============================================================
# COMMAND LINE ENTRY POINT
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print()

        print(
            "Usage:"
        )

        print(
            "python3 "
            "ml_engine/training/train_pipeline.py "
            "/path/to/dataset"
        )

        print()

        sys.exit(1)

    dataset_path = sys.argv[1]

    train_models(
        dataset_path
    )