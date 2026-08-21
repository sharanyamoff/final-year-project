# XRL-IDARS Dataset Mapping & Feature Schema (CIC-IDS2017)

## 1. Selected CIC-IDS2017 Files
The training pipeline supports processing the complete CIC-IDS2017 dataset to capture a comprehensive distribution of benign and attack traffic. The user must place the raw CSV files in `ml_engine/data/`.

*   `Monday-WorkingHours.pcap_ISCX.csv` (Benign)
*   `Tuesday-WorkingHours.pcap_ISCX.csv` (Benign, FTP-Patator, SSH-Patator)
*   `Wednesday-workingHours.pcap_ISCX.csv` (Benign, DoS variations, Heartbleed)
*   `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` (Benign, Web Attacks)
*   `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` (Benign, Infiltration)
*   `Friday-WorkingHours-Morning.pcap_ISCX.csv` (Benign, Bot)
*   `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` (Benign, PortScan)
*   `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (Benign, DDoS)

## 2. Project Label Taxonomy Update
The original prototype UI taxonomy (`DOS_SYN_FLOOD`, `MALWARE_C2_PROBE`, etc.) is scientifically inaccurate for grouping disparate CIC-IDS2017 attacks. The backend and UI `AttackType` enum MUST be refactored to align with the dataset. 

| CIC-IDS2017 Original Label | New Project Attack Class (`AttackType`) | Justification |
| :--- | :--- | :--- |
| `BENIGN` | `BENIGN` | Exact match. |
| `DDoS`, `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest` | `DOS_ATTACK` | Groups all Denial of Service attacks. These operate via different vectors (e.g., HTTP GET, Slowloris) and are explicitly NOT all SYN floods. We will update the UI to support this broader class. |
| `PortScan` | `PORT_SCAN` | Exact match. |
| `FTP-Patator`, `SSH-Patator` | `BRUTE_FORCE` | Groups credential stuffing and brute-force tools. |
| `Bot` | `BOTNET` | Distinct classification for botnet beaconing. |
| `Infiltration` | `INFILTRATION` | Distinct classification for internal network compromise. |
| `Web Attack \xbd Brute Force`, `Web Attack \xbd XSS`, `Web Attack \xbd Sql Injection`, `Heartbleed` | `WEB_ATTACK` | Distinct classification for Layer-7 HTTP anomalies. |

## 3. Exact 10-Feature Mapping (Dataset vs Live Scapy)
**Crucial Note on Packet Length:** CICFlowMeter (used to create CIC-IDS2017) defines packet length as the entire IP packet length (Header + Payload). The live Scapy extraction MUST use `len(packet[IP])` and NOT just the TCP payload length.

| Model Feature Name | CIC-IDS2017 Column | Mathematical Definition | Live Scapy Calculation |
| :--- | :--- | :--- | :--- |
| `flow_duration_ms` | ` Flow Duration` | Duration of flow. CIC is in microseconds. | Time difference (ms) between first and last packet in the 3-second window. |
| `flow_packets_per_s` | ` Flow Packets/s` | Total packets / duration in seconds. | `total_packets / max(0.001, duration_seconds)` |
| `flow_bytes_per_s` | ` Flow Bytes/s` | Total bytes / duration in seconds. | `sum(len(pkt[IP])) / max(0.001, duration_seconds)` |
| `packet_length_mean` | ` Packet Length Mean` | Mean of total IP packet sizes in the flow. | `sum(len(pkt[IP])) / total_packets` |
| `packet_length_std` | ` Packet Length Std` | Standard deviation of IP packet sizes. | $\sqrt{\frac{1}{N} \sum (x_i - \mu)^2}$ where $x_i$ is `len(pkt[IP])`. |
| `syn_count` | ` SYN Flag Count` | Absolute count of SYN packets. | Sum where `pkt[TCP].flags & SYN` |
| `ack_count` | ` ACK Flag Count` | Absolute count of ACK packets. | Sum where `pkt[TCP].flags & ACK` |
| `rst_count` | ` RST Flag Count` | Absolute count of RST packets. | Sum where `pkt[TCP].flags & RST` |
| `fin_count` | ` FIN Flag Count` | Absolute count of FIN packets. | Sum where `pkt[TCP].flags & FIN` |
| `syn_ack_ratio` | *Derived* | `SYN Flag Count` / max(1, `ACK Flag Count`). | `syn_count / max(1, ack_count)` |

## 4. LSTM Temporal Semantics vs Random Forest Flow Semantics
This pipeline implements a dual-view architecture:
1. **Random Forest = Instantaneous Flow-Level Classification:** Evaluates a single `(1x10)` feature vector representing a specific flow over the current window.
2. **LSTM = Temporal Host-Level Anomaly Detection:** Evaluates a host's behavioral trajectory over time. It groups flow vectors by **Source IP** in chronological order.
*   **Sequence Construction:** Sequences of length $T=5$ are created chronologically per Source IP.
*   **Padding/Masking:** We will NOT arbitrarily zero-pad sequences. During inference, the system will hold LSTM evaluation in a "PENDING" state until a minimum of 5 flows are observed from a given IP. If padding is ever mathematically required for batch alignment, we will use an explicit PyTorch attention mask or `pack_padded_sequence`.

## 5. Preprocessing & Leakage-Safe Split Strategy
1. **Preprocessing:** `StandardScaler` (Z-score normalization) is strictly required for the LSTM to ensure stable gradient descent. The Random Forest (being tree-based) is scale-invariant and does not mathematically require it, but we apply the same transformation uniformly to the pipeline for architectural consistency. The fitted `StandardScaler` is saved via `joblib`.
2. **Train/Validation/Test Split (Preventing Leakage):** 
   - Blind K-Fold or simple chronological splits risk either splitting highly correlated packets from the same microsecond burst across train/test sets, or failing entirely because specific attacks only occur on specific days in CIC-IDS2017.
   - **Strategy:** We will use a **Time-Binned Stratified Split**. We group flows into 5-minute contiguous time blocks based on Timestamp and Source IP. The split ensures that an entire 5-minute attack session falls entirely into Train, Validation, or Test. We then stratify these blocks by `AttackType` to guarantee the LSTM and RF see representation of all classes across the splits without leaking identical behavioral sequences.
