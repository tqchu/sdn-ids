#!/usr/bin/env python3
import csv, ipaddress, json, os, signal, sys
import pickle
from collections import defaultdict
from symbol import flow_stmt

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


def get_group_id(ip_dst: str, dst_port: int, proto: int):
    return f"{str(ip_dst)}_{str(dst_port)}_{str(proto)}"


def get_flow_id(ip_src: str, src_port: int, ip_dst: str, dst_port: int, proto: int):
    return f"{str(ip_src)}_{str(src_port)}_{str(ip_dst)}_{str(dst_port)}_{str(proto)}"


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


class GroupFlowCached:
    """Data structure to track features for a single bidirectional flow."""

    def __init__(self, group_id, start_time, forward_src, dst_ip, src_port, dst_port, protocol):
        self.group_id = group_id
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
        self.src_ips = []
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.src_ip_counts = 0
        self.flow_count = 0
        self.tot_pkts = 0
        self.tot_bytes = 0
        self.flow_ids = []

    def update(self, src_ip, src_port, direction, pkt_len, tcp_flags, timestamp, tcp_win=None):
        self.flow_packets += 1
        # Update flow last seen and duration
        self.last_seen = timestamp

        if (src_ip, src_port) not in self.src_ips and direction == "fwd":
            self.src_ip_counts += 1
            self.src_ips.append((src_ip, src_port))
            self.flow_count += 1
            self.flow_ids.append(get_flow_id(src_ip, src_port, self.dst_ip, self.dst_port, self.protocol))

        self.tot_pkts += 1
        self.tot_bytes += pkt_len

        if direction == 'fwd':
            self.tot_fwd_pkts += 1
            self.tot_fwd_bytes += pkt_len
            self.fwd_lens.append(pkt_len)
            self.last_seen_fwd = timestamp
        else:  # 'bwd' direction
            self.tot_bwd_pkts += 1
            self.tot_bwd_bytes += pkt_len
            self.bwd_lens.append(pkt_len)
            self.last_seen_bwd = timestamp

    def get_features(self):
        duration = (self.last_seen - self.start_time) // 1e3  # convert to microseconds if needed

        pkts_per_sec = (self.flow_packets / (duration / 1e6)) if duration > 0 else 0
        # pkts_per_sec = (self.flow_packets / 10)

        bytes_per_sec = ((self.tot_fwd_bytes + self.tot_bwd_bytes) / (duration / 1e6)) if duration > 0 else 0
        # bytes_per_sec = ((self.tot_fwd_bytes + self.tot_bwd_bytes) / 10)

        pkts_per_src_ip = self.tot_pkts/ self.src_ip_counts if self.src_ip_counts > 0 else 0
        bytes_per_src_ip = self.tot_bytes / self.src_ip_counts if self.src_ip_counts > 0 else 0
        return {
            "total_src_ips": self.src_ip_counts,
            "flow_count": self.tot_pkts,
            "Tot Fwd Pkts": self.tot_fwd_pkts,
            "Tot Bwd Pkts": self.tot_bwd_pkts,
            "TotLen Fwd Pkts": self.tot_fwd_bytes,
            "TotLen Bwd Pkts": self.tot_bwd_bytes,
            "Flow Pkts/s": pkts_per_sec,
            "Flow Byts/s": bytes_per_sec,
            # "Flow Duration": duration,
            "Flow Duration": 5,
            "total_pkts": self.tot_pkts,
            "total_bytes": self.tot_bytes,
            "pkts_per_src_ip": pkts_per_src_ip,
            "bytes_per_src_ip": bytes_per_src_ip,

            "Group ID": self.group_id,
            "Src IPs": self.src_ips,
            "Src Port": self.src_port,
            "Dst IP": self.dst_ip,
            "Dst Port": self.dst_port,
            "Protocol": self.protocol,

            "Timestamp": self.last_seen,

            # "total_src_ips": 1,
            # "flow_count": 45,
            # "Tot Fwd Pkts": 45,
            # "Tot Bwd Pkts": 45,
            # "TotLen Fwd Pkts": 0.0,
            # "TotLen Bwd Pkts": 0.0,
            # "Flow Pkts/s": 2000000.0,
            # "Flow Byts/s": 0.0,
            # "Flow Duration": 1.0,
            # "total_pkts": 45,
            # "total_bytes": 0.0,
            # "pkts_per_src_ip": 45.0,
            # "bytes_per_src_ip": 0.0,
            # "Group ID": self.group_id,
            # "Src IPs": self.src_ips,
            # "Src Port": self.src_port,
            # "Dst IP": self.dst_ip,
            # "Dst Port": self.dst_port,
            # "Protocol": self.protocol,
            #
            # "Timestamp": self.last_seen,
        }


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
            self.last_seen_fwd = timestamp
        else:  # 'bwd' direction
            self.tot_bwd_pkts += 1
            self.tot_bwd_bytes += pkt_len
            self.bwd_lens.append(pkt_len)
            self.last_seen_bwd = timestamp

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
        }


cache_flows = {}
cached_groups = {}
block_flows = []

save_duration = 10
detect_duration = 10
last_saved = time.time()
last_detected = time.time()

with open(
        'models/best_flow_model.pkl',
        'rb') as f:
    flow_model = pickle.load(f)

with open(
        'models/flow_scaler.pkl',
        'rb') as f:
    flow_scaler = pickle.load(f)

with open(
        'models/best_group_model.pkl',
        'rb') as f:
    group_model = pickle.load(f)

with open(
        'models/group_scaler.pkl',
        'rb') as f:
    group_scaler = pickle.load(f)

ensure_csv_header()

group_features_col = [
    "total_src_ips",
    "flow_count",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Flow Pkts/s",
    "Flow Byts/s",
    "Flow Duration",
    "total_pkts",
    "total_bytes",
    "pkts_per_src_ip",
    "bytes_per_src_ip",
    "Group ID",
    "Src IPs",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Timestamp",
]

flow_features_col = [
    "Src IP",
    "Flow ID",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
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
        flow = FlowCached(flow_id=flow_id, start_time=flow_msg.time_flow_start_ns, forward_src=ip_src,
                          src_ip=ip_src,
                          dst_ip=ip_dst, src_port=src_port, dst_port=dst_port, protocol=flow_msg.proto)
        cache_flows[flow_id] = flow

    direction = 'fwd' if ip_src == flow.forward_src else 'bwd'

    flow.update(direction, flow_msg.bytes, None, flow_msg.time_flow_start_ns)

    group_id = get_group_id(
        ip_dst=ip_dst,
        dst_port=dst_port,
        proto=flow_msg.proto,
    )

    if group_id not in cached_groups:
        fwd_group = GroupFlowCached(
            group_id=group_id,
            start_time=flow_msg.time_flow_start_ns,
            forward_src=ip_src,
            dst_ip=ip_dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=flow_msg.proto
        )
        cached_groups[group_id] = fwd_group
    else:
        fwd_group = cached_groups[group_id]

    fwd_group.update(ip_src, src_port, "fwd", flow_msg.bytes, None, flow_msg.time_flow_start_ns)

    rev_group_id = get_group_id(
        ip_dst=ip_src,
        dst_port=src_port,
        proto=flow_msg.proto,
    )

    if rev_group_id not in cached_groups:
        bwd_group = GroupFlowCached(
            group_id=rev_group_id,
            start_time=flow_msg.time_flow_start_ns,
            forward_src=ip_dst,
            dst_ip=ip_src,
            src_port=dst_port,
            dst_port=src_port,
            protocol=flow_msg.proto
        )
        cached_groups[rev_group_id] = bwd_group
    else:
        bwd_group = cached_groups[rev_group_id]

    bwd_group.update(ip_src, src_port, "bwd", flow_msg.bytes, None, flow_msg.time_flow_start_ns)

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

    if time.time() - last_detected > detect_duration:
        features = []

        # group id
        for fwd_group, saved_group in cached_groups.items():
            if saved_group.flow_packets > 1:
                data = saved_group.get_features()
                # Only include the columns specified in features_col
                features.append(data)

        if not features:
            continue

        # X = pd.DataFrame(features)[["Flow Duration","Tot Fwd Pkts","Tot Bwd Pkts","TotLen Fwd Pkts","TotLen Bwd Pkts","Flow Byts/s","Flow Pkts/s","total_src_ips","flow_count","total_pkts","total_bytes","pkts_per_src_ip","bytes_per_src_ip"]]
        X = pd.DataFrame(features)
        print("Features", features)

        drop_cols = ["Group ID", "Src IPs", "Src Port", "Dst IP",
                     "Dst Port", "Protocol", "Timestamp"]

        X = X.drop(columns=drop_cols)

        X = group_scaler.transform(X)
        y = group_model.predict(X)

        for i, yi in enumerate(y):
            if yi == 'Normal':
                print("Normal")
                print("Group ID", features[i]["Group ID"])
                print("Info", features[i])

            if yi != 'Normal':
                print("Attack Detected: ", yi)

                xi = features[i]

                group_id = xi["Group ID"]
                print("Detected malicious group id: %s", group_id)

                group_flows = []

                # detect that group flows
                for src_ip, src_port in xi["Src IPs"]:
                    flow_id = get_flow_id(
                        src_ip, src_port,
                        xi["Dst IP"], xi["Dst Port"],
                        xi["Protocol"]
                    )

                    if flow_id in cache_flows:
                        group_flows.append(cache_flows[flow_id].get_features())

                if not group_flows:
                    continue

                drop_cols = [
                    "Flow ID",
                    "Src IP",
                    "Dst IP",
                    "Timestamp"]
                flows_X = pd.DataFrame(group_flows)

                flows_X = flows_X.drop(columns=drop_cols)

                flows_X = flow_scaler.transform(flows_X)

                flows_y = flow_model.predict(flows_X)

                for j, flow_yi in enumerate(flows_y):
                    print("Flow prediction", flow_yi)
                    if flow_yi == yi:
                        flow_xi = features[j]
                        flow_id = flow_xi["Flow ID"]
                        print("Detected malicious flow: %s", flow_id)

                        flow_tuple = (
                            flow_xi["Src IP"], flow_xi["Dst IP"],
                            flow_xi["Src Port"], flow_xi["Dst Port"]
                        )
                        proto = flow_xi["Protocol"]

                        # block_flow(flow_tuple, proto)
                        print("Blocked malicious flow", flow_tuple, proto)
                        block_flows.append((flow_tuple, proto))

                        # Alert the attack using the alerter
                        alerter.handle_detection(flow_id, yi, xi)

        cache_flows = {}
        cached_groups = {}
        last_detected = time.time()

        # # flow detection
        # for flow_id, saved_flow in cache_flows.items():
        #     if saved_flow.flow_packets > 1:
        #         data = saved_flow.get_features()
        #         # Only include the columns specified in features_col
        #         features.append({col: data[col] for col in flow_features_col if col in data})
        #
        # if not features:
        #     continue
        #
        # X = pd.DataFrame(features)[[col for col in flow_features_col if col not in ["Flow ID", "Src IP", "Dst IP"]]]
        # X = scaler.transform(X)
        # y = model.predict(X)
        #
        # print("Prediction %s", y)
        #
        # for i, yi in enumerate(y):
        #     if yi != 'Normal':
        #         print("Attack Detected: %s", yi)
        #
        #         xi = features[i]
        #
        #         flow_id = xi["Flow ID"]
        #         print("Detected flow: %s", flow_id)
        #
        #         flow_tuple = (
        #             xi["Src IP"], xi["Dst IP"],
        #             xi["Src Port"], xi["Dst Port"]
        #         )
        #         proto = xi["Protocol"]  # numeric 1/6/17 …
        #
        #         block_flow(flow_tuple, proto)
        #         print("Blocked malicious flow", flow_tuple, proto)
        #         block_flows.append((flow_tuple, proto))
        #
        #         # Remove the flow from cache_flows dictionary
        #         del cache_flows[flow_id]  # Use the flow_id of the detected attack
        #
        #         # Alert the attack using the alerter
        #         alerter.handle_detection(flow_id, yi, xi)
        #
        # last_detected = time.time()
        #
        # # flush cached
        # cache_flows = {}

        # CSV append (only selected columns)
