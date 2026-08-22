#!/usr/bin/env python3

import sys
import json
import argparse
import time
import statistics
import uuid
from collections import defaultdict
import threading
from queue import Queue

import requests
from scapy.all import sniff, IP, TCP, UDP, ICMP

API_URL = "http://127.0.0.1:8000/predict"

WINDOW_SECONDS = 5.0

prediction_queue = Queue()

def prediction_worker():
    while True:
        job = prediction_queue.get()
        if job is None:
            break
        try:
            response = requests.post(
                API_URL,
                json=job["payload"],
                timeout=5
            )
            print(json.dumps({
                "type": "prediction",
                "flow": job["flow_info"],
                "features": job["features"],
                "prediction": response.json()
            }), flush=True)
        except requests.exceptions.RequestException as e:
            print(json.dumps({
                "type": "prediction_error",
                "error": str(e)
            }), flush=True)
        prediction_queue.task_done()

threading.Thread(target=prediction_worker, daemon=True).start()

flows = defaultdict(lambda: {
    "start_time": None,
    "last_time": None,
    "packet_sizes": [],
    "syn_count": 0,
    "ack_count": 0,
    "rst_count": 0,
    "fin_count": 0,
    "packets": 0,
    "bytes": 0,
    "sequence": [],
    "last_predict_time": 0.0
})


def get_protocol(packet):
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    return "OTHER"


def get_flow_key(packet):
    if IP not in packet:
        return None

    src = packet[IP].src
    dst = packet[IP].dst

    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        proto = "TCP"

    elif UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        proto = "UDP"

    else:
        sport = 0
        dport = 0
        proto = get_protocol(packet)

    return (
        src,
        dst,
        sport,
        dport,
        proto
    )


def update_flow(packet):
    key = get_flow_key(packet)

    if key is None:
        return

    now = time.time()
    size = len(packet)

    flow = flows[key]

    if flow["start_time"] is not None and (now - flow["start_time"] >= WINDOW_SECONDS):
        seq = flow["sequence"]
        last_predict = flow["last_predict_time"]
        flow.clear()
        flow.update({
            "start_time": now,
            "last_time": now,
            "packet_sizes": [],
            "syn_count": 0,
            "ack_count": 0,
            "rst_count": 0,
            "fin_count": 0,
            "packets": 0,
            "bytes": 0,
            "sequence": seq,
            "last_predict_time": last_predict
        })
    elif flow["start_time"] is None:
        flow["start_time"] = now

    flow["last_time"] = now

    flow["packets"] += 1
    flow["bytes"] += size
    flow["packet_sizes"].append(size)

    syn = 0
    ack = 0
    rst = 0
    fin = 0

    if TCP in packet:

        flags = packet[TCP].flags

        if "S" in flags:
            syn = 1
            flow["syn_count"] += 1

        if "A" in flags:
            ack = 1
            flow["ack_count"] += 1

        if "R" in flags:
            rst = 1
            flow["rst_count"] += 1

        if "F" in flags:
            fin = 1
            flow["fin_count"] += 1

    # Keep temporal information for LSTM
    flow["sequence"].append(build_features(flow))

    # Keep last 5 observations
    flow["sequence"] = flow["sequence"][-5:]

    return key


def build_features(flow):
    duration = max(
        (flow["last_time"] or 0) -
        (flow["start_time"] or 0),
        0.001
    )

    packets_per_second = flow["packets"] / duration

    bytes_per_second = flow["bytes"] / duration

    sizes = flow["packet_sizes"]

    mean_size = statistics.mean(sizes) if sizes else 0.0

    std_size = (
        statistics.stdev(sizes)
        if len(sizes) > 1
        else 0.0
    )

    syn_count = flow["syn_count"]
    ack_count = flow["ack_count"]

    syn_ack_ratio = (
        ack_count / syn_count
        if syn_count > 0
        else 0.0
    )

    return {
        "flow_duration_ms": float(duration * 1000),
        "flow_packets_per_s": float(packets_per_second),
        "flow_bytes_per_s": float(bytes_per_second),
        "packet_length_mean": float(mean_size),
        "packet_length_std": float(std_size),
        "syn_count": float(flow["syn_count"]),
        "ack_count": float(flow["ack_count"]),
        "rst_count": float(flow["rst_count"]),
        "fin_count": float(flow["fin_count"]),
        "syn_ack_ratio": float(syn_ack_ratio)
    }


def build_sequence(flow):
    """
    Convert the captured flow into the exact
    10-feature format expected by the LSTM.

    Until we have enough real observations,
    repeat the current feature vector.
    """

    sequence = list(flow["sequence"])

    if len(sequence) < 5:
        pad_size = 5 - len(sequence)
        zero_pad = {k: 0.0 for k in sequence[0].keys()}
        sequence = [zero_pad] * pad_size + sequence

    return sequence


def send_prediction(key, flow):

    features = build_features(flow)
    sequence = build_sequence(flow)
    flow_id = str(uuid.uuid4())

    payload = {
        "flow_id": flow_id,
        "features": features,
        "sequence": sequence,
        "env_state": {
            "historical_incident_count": 0.0,
            "is_blocked": 0.0
        }
    }

    prediction_queue.put({
        "flow_info": {
            "source_ip": key[0],
            "destination_ip": key[1],
            "source_port": key[2],
            "destination_port": key[3],
            "protocol": key[4]
        },
        "features": features,
        "payload": payload
    })


def packet_callback(packet):

    try:

        if IP not in packet:
            return

        key = update_flow(packet)

        if key is None:
            return

        flow = flows[key]
        now = time.time()
        
        # Rate limit predictions to once per second per flow to avoid ML API overload
        if now - flow["last_predict_time"] >= 1.0:
            flow["last_predict_time"] = now
            send_prediction(key, flow)

    except Exception as e:

        print(
            json.dumps({
                "type": "sniffer_error",
                "error": str(e)
            }),
            flush=True
        )


def main():

    parser = argparse.ArgumentParser(
        description="XRL-IDARS Scapy Live Sniffer"
    )

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Network interface"
    )

    parser.add_argument(
        "-f",
        "--filter",
        default="",
        help="BPF filter"
    )

    args = parser.parse_args()

    print(
        json.dumps({
            "status": "started",
            "interface": args.interface,
            "filter": args.filter,
            "api": API_URL
        }),
        flush=True
    )

    try:

        # Verify ML API before sniffing.
        response = requests.get(
            "http://127.0.0.1:8000/health",
            timeout=5
        )

        print(
            json.dumps({
                "api_health": response.json()
            }),
            flush=True
        )

    except Exception as e:

        print(
            json.dumps({
                "api_health_error": str(e)
            }),
            flush=True
        )

        sys.exit(1)

    try:

        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=packet_callback,
            store=0
        )

    except KeyboardInterrupt:

        print(
            json.dumps({
                "status": "stopped"
            }),
            flush=True
        )

    except Exception as e:

        print(
            json.dumps({
                "error": str(e)
            }),
            flush=True
        )

        sys.exit(1)


if __name__ == "__main__":
    main() 
