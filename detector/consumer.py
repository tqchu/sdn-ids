#!/usr/bin/env python3
import csv, ipaddress, json, os, signal, sys
import pickle

from kafka import KafkaConsumer
import google.protobuf.internal.decoder as _dec

from alerter.ai_alerter import AIAttackAlerter
from detector import flow_pb2
import pandas as pd
import time

from detector.blocker import block_flow

print("Start consumer")

TOPIC = "flows"
BROKERS = [os.environ.get('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')]
CSV_FILE = "flows.csv"
HEADERS = [
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Byts/s",
    "Flow Pkts/s"]

consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers=BROKERS,
    auto_offset_reset="latest",
    value_deserializer=lambda v: v  # raw bytes
)


def strip_len(buf: bytes):
    n, p = _dec._DecodeVarint(buf, 0)
    return buf[p:p + n]


def bytes_to_ip(b: bytes):
    try:
        return str(ipaddress.ip_address(b))
    except ValueError:
        return ""


def int_to_mac(x: int):
    return ":".join(f"{(x >> (8 * i)) & 0xff:02x}" for i in reversed(range(6)))


def ensure_csv_header():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            csv.writer(f).writerow(HEADERS)


def rewrite_csv(csv_file):
    with open(csv_file, "w", newline="") as f:
        csv.writer(f).writerow(HEADERS)


def sigterm(*_): sys.exit(0)


signal.signal(signal.SIGINT, sigterm);
signal.signal(signal.SIGTERM, sigterm)


class FlowCached:
    """Data structure to track features for a single bidirectional flow."""

    def __init__(self, flow_id, start_time, forward_src, src_ip, dst_ip, src_port, dst_port, protocol):
        self.flow_id = flow_id
        self.last_seen = start_time
        self.start_time = start_time
        self.forward_src = forward_src
        self.tot_fwd_pkts = 0
        self.tot_bwd_pkts = 0
        self.tot_fwd_bytes = 0
        self.tot_bwd_bytes = 0
        self.fwd_lens = []  # will hold lengths of forward packets
        self.bwd_lens = []  # will hold lengths of forward packets
        self.last_seen_fwd = start_time
        self.last_seen_bwd = start_time
        self.flow_packets = 0
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

    def update(self, direction, pkt_len, tcp_flags, timestamp, tcp_win=None):
        self.flow_packets += 1
        # Update flow last seen and duration
        self.last_seen = timestamp

        if direction == 'fwd':
            self.tot_fwd_pkts += 1
            self.tot_fwd_bytes += pkt_len
            self.fwd_lens.append(pkt_len)
            # Inter-arrival time for forward packets
            # if self.tot_fwd_pkts > 1:  # if not the first fwd packet
            #     iat = timestamp - self.last_seen_fwd
            #     self.fwd_iat.append(iat)
            self.last_seen_fwd = timestamp
            # TCP flag specifics for forward packet
            # if tcp_flags:
            #     # Check each relevant flag bit (using TCP flag bit values)
            #     if tcp_flags & 0x08:  # PSH flag bit (0x08) set
            #         self.fwd_psh_count += 1
            #     if tcp_flags & 0x20:  # URG flag bit (0x20) set
            #         self.fwd_urg_count += 1
        else:  # 'bwd' direction
            self.tot_bwd_pkts += 1
            self.tot_bwd_bytes += pkt_len
            self.bwd_lens.append(pkt_len)
            # if self.tot_bwd_pkts > 1:
            #     iat = timestamp - self.last_seen_bwd
            #     self.bwd_iat.append(iat)
            self.last_seen_bwd = timestamp
            # if tcp_flags:
            #     if tcp_flags & 0x08:
            #         self.bwd_psh_count += 1
            #     if tcp_flags & 0x20:
            #         self.bwd_urg_count += 1

    def get_features(self):
        duration = (self.last_seen - self.start_time) // 1e3  # convert to microseconds if needed

        fwd_len_mean = (sum(self.fwd_lens) / len(self.fwd_lens)) if self.fwd_lens else 0
        fwd_len_std = (pd.Series(self.fwd_lens).std() if len(self.fwd_lens) > 1 else 0)  # or manual std
        fwd_len_max = max(self.fwd_lens) if self.fwd_lens else 0
        fwd_len_min = min(self.fwd_lens) if self.fwd_lens else 0

        bwd_len_mean = (sum(self.bwd_lens) / len(self.bwd_lens)) if self.bwd_lens else 0
        bwd_len_std = (pd.Series(self.bwd_lens).std() if len(self.bwd_lens) > 1 else 0)  # or manual std
        bwd_len_max = max(self.bwd_lens) if self.bwd_lens else 0
        bwd_len_min = min(self.bwd_lens) if self.bwd_lens else 0

        pkts_per_sec = (self.flow_packets / (duration / 1e6)) if duration > 0 else 0
        bytes_per_sec = ((self.tot_fwd_bytes + self.tot_bwd_bytes) / (duration / 1e6)) if duration > 0 else 0

        return {
            "Flow ID": self.flow_id,
            "Src IP": self.src_ip,
            "Src Port": self.src_port,
            "Dst IP": self.dst_ip,
            "Dst Port": self.dst_port,
            "Protocol": self.protocol,

            "Timestamp": self.last_seen,
            "Flow Duration": duration,
            "Tot Fwd Pkts": self.tot_fwd_pkts,
            "Tot Bwd Pkts": self.tot_bwd_pkts,
            #
            "TotLen Fwd Pkts": self.tot_fwd_bytes,
            "TotLen Bwd Pkts": self.tot_bwd_bytes,
            #
            "Fwd Pkt Len Max": fwd_len_max,
            "Fwd Pkt Len Min": fwd_len_min,
            "Fwd Pkt Len Mean": fwd_len_mean,
            "Fwd Pkt Len Std": fwd_len_std,
            #
            "Bwd Pkt Len Max": bwd_len_max,
            "Bwd Pkt Len Min": bwd_len_min,
            "Bwd Pkt Len Mean": bwd_len_mean,
            "Bwd Pkt Len Std": bwd_len_std,
            #
            "Flow Byts/s": bytes_per_sec,
            "Flow Pkts/s": pkts_per_sec,
            #
            # "Flow IAT Mean":,
            # "Flow IAT Std":,
            # "Flow IAT Max":,
            # "Flow IAT Min":,
            # "Fwd IAT Tot":,
            #
            # "Fwd IAT Mean":,
            # "Fwd IAT Std":,
            # "Fwd IAT Max":,
            # "Fwd IAT Min":,
            #
            # "Bwd IAT Tot":,
            # "Bwd IAT Mean":,
            # "Bwd IAT Std":,
            # "Bwd IAT Max":,
            #
            # "Bwd IAT Min":,
            # "Fwd PSH Flags":,
            # "Bwd PSH Flags":,
            # "Fwd URG Flags":,
            #
            # "Bwd URG Flags":,
            # "Fwd Header Len":,
            # "Bwd Header Len":,
            # "Fwd Pkts/s":,
            #
            # "Bwd Pkts/s":,
            # "Pkt Len Min":,
            # "Pkt Len Max":,
            # "Pkt Len Mean":,
            #
            # "Pkt Len Std":,
            # "Pkt Len Var":,
            # "FIN Flag Cnt":,
            # "SYN Flag Cnt":,
            #
            # "RST Flag Cnt":,
            # "PSH Flag Cnt":,
            # "ACK Flag Cnt":,
            # "URG Flag Cnt":,
            #
            # "CWE Flag Count":,
            # "ECE Flag Cnt":,
            # "Down/Up Ratio":,
            # "Pkt Size Avg":,
            #
            # "Fwd Seg Size Avg":,
            # "Bwd Seg Size Avg":,
            # "Fwd Byts/b Avg":,
            #
            # "Fwd Pkts/b Avg":,
            # "Fwd Blk Rate Avg":,
            # "Bwd Byts/b Avg":,
            #
            # "Bwd Pkts/b Avg":,
            # "Bwd Blk Rate Avg":,
            # "Subflow Fwd Pkts":,
            #
            # "Subflow Fwd Byts":,
            # "Subflow Bwd Pkts":,
            # "Subflow Bwd Byts":,
            #
            # "Init Fwd Win Byts":,
            # "Init Bwd Win Byts":,
            # "Fwd Act Data Pkts":,
            #
            # "Fwd Seg Size Min":,
            # "Active Mean":,
            # "Active Std":,
            # "Active Max":,
            #
            # "Active Min":,
            # "Idle Mean":,
            # "Idle Std":,
            # "Idle Max":,
            # "Idle Min":,
            # "Label"
        }


cache_flows = {}

block_flows = []

save_duration = 5
detect_duration = 5
last_saved = time.time()
last_detected = time.time()

with open(
        'models/best_model.pkl',
        'rb') as f:
    model = pickle.load(f)

with open(
        'models/scaler.pkl',
        'rb') as f:
    scaler = pickle.load(f)

ensure_csv_header()
features_col = [
    # "Flow Duration",
    # "Active Mean","Idle Mean", "Tot Fwd Pkts","TotLen Fwd Pkts",
    # "Flow Pkts/s","Flow Byts/s"
    # "Flow ID",
    "Src IP",
    "Flow ID",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
    # "Timestamp",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Byts/s",
    "Flow Pkts/s"
]

# Initialize the alerter
alerter = AIAttackAlerter(
    pushgateway_url=os.environ.get('PUSHGATEWAY_URL', 'localhost:9091'),
    loki_url=os.environ.get('LOKI_URL', 'http://localhost:3100'))

# ignore if the flow is empty or already blocked
for msg in consumer:
    flow_msg = flow_pb2.FlowMessage()
    flow_msg.ParseFromString(strip_len(msg.value))

    if flow_msg.packets == 0:
        continue

    ip_src = bytes_to_ip(flow_msg.src_addr)
    ip_dst = bytes_to_ip(flow_msg.dst_addr)

    flow_tuple = (
        ip_src, ip_dst,
        getattr(flow_msg, "src_port", 0), getattr(flow_msg, "dst_port", 0)
    )
    proto = flow_msg.proto

    if (flow_tuple, proto) in block_flows:
        continue

    src_port = getattr(flow_msg, "src_port", 0)
    dst_port = getattr(flow_msg, "dst_port", 0)

    if ip_src == "" or ip_dst == "":
        continue

    flow_id = f"{str(ip_src)}_{str(src_port)}_{str(ip_dst)}_{str(dst_port)}_{str(flow_msg.proto)}"

    rev_key = f"{str(ip_dst)}_{str(dst_port)}_{str(ip_src)}_{str(src_port)}_{str(flow_msg.proto)}"

    if flow_id in cache_flows:
        flow = cache_flows[flow_id]
    elif rev_key in cache_flows:
        flow = cache_flows[rev_key]
    else:
        flow = FlowCached(flow_id=flow_id, start_time=flow_msg.time_flow_start_ns, forward_src=ip_src, src_ip=ip_src,
                          dst_ip=ip_dst, src_port=src_port, dst_port=dst_port, protocol=flow_msg.proto)
        cache_flows[flow_id] = flow

    direction = 'fwd' if ip_src == flow.forward_src else 'bwd'

    flow.update(direction, flow_msg.packets, None, flow_msg.time_flow_start_ns)

    # build human-readable dict
    # d = flow.get_features()

    # STDOUT one-line JSON
    # print(json.dumps(d, separators=(',', ':')))
    # sys.stdout.flush()

    # if time.time() - last_saved > save_duration:
    #     csv_file = f"flows/flows_{time.time()}.csv"
    #     rewrite_csv(csv_file)
    #
    #     with open(csv_file, "a", newline="") as f:
    #         writer = csv.writer(f)
    #         for flow_id, saved_flow in cache_flows.items():
    #             data = saved_flow.get_features()
    #             writer.writerow([data[h] for h in HEADERS])
    #
    #     last_saved = time.time()

    if time.time() - last_detected > save_duration:
        features = []
        for flow_id, saved_flow in cache_flows.items():
            if saved_flow.flow_packets > 1:
                data = saved_flow.get_features()
                # Only include the columns specified in features_col
                features.append({col: data[col] for col in features_col if col in data})

        if not features:
            continue

        X = pd.DataFrame(features)[[col for col in features_col if col not in ["Flow ID", "Src IP", "Dst IP"]]]
        X = scaler.transform(X)
        y = model.predict(X)

        print("Prediction %s", y)

        for i, yi in enumerate(y):
            if yi != 'Normal':
                print("Attack Detected: %s", yi)

                xi = features[i]

                flow_id = xi["Flow ID"]
                print("Detected flow: %s", flow_id)

                flow_tuple = (
                    xi["Src IP"], xi["Dst IP"],
                    xi["Src Port"], xi["Dst Port"]
                )
                proto = xi["Protocol"]  # numeric 1/6/17 …

                block_flow(flow_tuple, proto)
                print("Blocked malicious flow", flow_tuple, proto)
                block_flows.append((flow_tuple, proto))

                # Remove the flow from cache_flows dictionary
                del cache_flows[flow_id]  # Use the flow_id of the detected attack

                # Alert the attack using the alerter
                alerter.handle_detection(flow_id, yi, xi)

        last_detected = time.time()
        # CSV append (only selected columns)
