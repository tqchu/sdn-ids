from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
import pandas as pd


class FlowFeatures:
    """Data structure to track features for a single bidirectional flow."""

    def __init__(self, flow_id, src_ip, src_port, dst_ip, dst_port, protocol, start_time):
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_id = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        # Timestamps
        self.start_time = start_time
        self.last_seen = start_time
        self.last_seen_fwd = start_time
        self.last_seen_bwd = start_time
        self.src_port = src_port
        # Identify forward direction by first packet's source
        self.forward_src = None
        # Packet and byte counts
        self.tot_fwd_pkts = 0
        self.tot_bwd_pkts = 0
        self.tot_fwd_bytes = 0
        self.tot_bwd_bytes = 0
        # Packet length tracking for stats
        self.fwd_lens = []  # will hold lengths of forward packets
        self.bwd_lens = []  # lengths of backward packets
        # Inter-arrival times (IAT)
        self.fwd_iat = []  # inter-arrival times for fwd packets
        self.bwd_iat = []  # inter-arrival times for bwd packets
        # TCP flag counters
        self.fwd_psh_count = 0
        self.bwd_psh_count = 0
        self.fwd_urg_count = 0
        self.bwd_urg_count = 0
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.ece_count = 0
        self.cwe_count = 0
        # Other features (some shown for illustration)
        self.init_fwd_win_bytes = None
        self.init_bwd_win_bytes = None
        self.flow_packets = 0  # total packets (both directions)
        # (Active/Idle tracking could be added here)

    def update(self, direction, pkt_len, tcp_flags, timestamp, tcp_win=None):
        """Update flow features with a new packet."""
        # Update global flow counters
        self.flow_packets += 1
        # Update flow last seen and duration
        self.last_seen = timestamp
        # Determine direction and update directional stats
        if direction == 'fwd':
            self.tot_fwd_pkts += 1
            self.tot_fwd_bytes += pkt_len
            self.fwd_lens.append(pkt_len)
            # Inter-arrival time for forward packets
            if self.tot_fwd_pkts > 1:  # if not the first fwd packet
                iat = timestamp - self.last_seen_fwd
                self.fwd_iat.append(iat)
            self.last_seen_fwd = timestamp
            # TCP flag specifics for forward packet
            if tcp_flags:
                # Check each relevant flag bit (using TCP flag bit values)
                if tcp_flags & 0x08:  # PSH flag bit (0x08) set
                    self.fwd_psh_count += 1
                if tcp_flags & 0x20:  # URG flag bit (0x20) set
                    self.fwd_urg_count += 1
        else:  # 'bwd' direction
            self.tot_bwd_pkts += 1
            self.tot_bwd_bytes += pkt_len
            self.bwd_lens.append(pkt_len)
            if self.tot_bwd_pkts > 1:
                iat = timestamp - self.last_seen_bwd
                self.bwd_iat.append(iat)
            self.last_seen_bwd = timestamp
            if tcp_flags:
                if tcp_flags & 0x08:
                    self.bwd_psh_count += 1
                if tcp_flags & 0x20:
                    self.bwd_urg_count += 1
        # Update overall TCP flag counts if applicable (count all packets)
        if tcp_flags:
            if tcp_flags & 0x01: self.fin_count += 1  # FIN
            if tcp_flags & 0x02: self.syn_count += 1  # SYN
            if tcp_flags & 0x04: self.rst_count += 1  # RST
            if tcp_flags & 0x08: self.psh_count += 1  # PSH
            if tcp_flags & 0x10: self.ack_count += 1  # ACK
            if tcp_flags & 0x20: self.urg_count += 1  # URG
            if tcp_flags & 0x40: self.ece_count += 1  # ECE
            if tcp_flags & 0x80: self.cwe_count += 1  # CWR (or CWE)
        # Record initial window size if provided (first packet of each side)
        if tcp_win is not None:
            if direction == 'fwd' and self.init_fwd_win_bytes is None:
                self.init_fwd_win_bytes = tcp_win
            elif direction == 'bwd' and self.init_bwd_win_bytes is None:
                self.init_bwd_win_bytes = tcp_win

    def get_features(self):
        duration = (self.last_seen - self.start_time) * 1e6  # convert to microseconds if needed



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
            # "Flow ID": self.flow_id,
         # "Src IP": self.src_ip,
         "Src Port": self.src_port,
         # "Dst IP": self.dst_id,
         "Dst Port": self.dst_port,
         # "Protocol": self.protocol,

        # "Timestamp":,
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
        "Bwd Pkt Len Min" :bwd_len_min,
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

    def compute_derived_features(self):
        """Compute features like means, standard deviations, durations, etc."""
        duration = (self.last_seen - self.start_time) * 1e6  # convert to microseconds if needed
        # Packet length stats
        fwd_len_mean = (sum(self.fwd_lens) / len(self.fwd_lens)) if self.fwd_lens else 0
        fwd_len_std = (pd.Series(self.fwd_lens).std() if len(self.fwd_lens) > 1 else 0)  # or manual std
        # (In practice, use numpy/pandas for std if available, or maintain running variance)
        # Similarly for bwd and combined lengths...
        # Inter-arrival time stats
        flow_iats = self.fwd_iat + self.bwd_iat
        flow_iat_mean = sum(flow_iats) / len(flow_iats) if flow_iats else 0
        flow_iat_max = max(flow_iats) if flow_iats else 0
        flow_iat_min = min(flow_iats) if flow_iats else 0
        # ... similarly compute std if needed.
        # Packet rate features
        pkts_per_sec = (self.flow_packets / (duration / 1e6)) if duration > 0 else 0
        bytes_per_sec = ((self.tot_fwd_bytes + self.tot_bwd_bytes) / (duration / 1e6)) if duration > 0 else 0
        # Down/Up ratio
        down_up_ratio = (self.tot_fwd_pkts / self.tot_bwd_pkts) if self.tot_bwd_pkts > 0 else float('inf')
        # (Compute other features like Idle/Active times if implemented)
        # Return a dictionary or list of all features computed
        return {
            "Flow Duration": duration,
            "Tot Fwd Pkts": self.tot_fwd_pkts,
            "Tot Bwd Pkts": self.tot_bwd_pkts,
            "TotLen Fwd Pkts": self.tot_fwd_bytes,
            "TotLen Bwd Pkts": self.tot_bwd_bytes,
            "Fwd Pkt Len Mean": fwd_len_mean,
            "Fwd Pkt Len Std": fwd_len_std,
            # ... (other features omitted for brevity)
            "Flow Pkts/s": pkts_per_sec,
            "Flow Byts/s": bytes_per_sec,
            "Down/Up Ratio": down_up_ratio,
            "FIN Flag Cnt": self.fin_count,
            "SYN Flag Cnt": self.syn_count,
            "RST Flag Cnt": self.rst_count,
            "PSH Flag Cnt": self.psh_count,
            "ACK Flag Cnt": self.ack_count,
            "URG Flag Cnt": self.urg_count,
            "CWE Flag Count": self.cwe_count,
            "ECE Flag Cnt": self.ece_count,
            # etc...
        }
