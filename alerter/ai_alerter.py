import time
import json
from collections import defaultdict
import requests
from prometheus_client import CollectorRegistry, Gauge, Counter, push_to_gateway, Histogram, Summary


class AIAttackAlerter:
    registry = CollectorRegistry()

    # Prometheus metrics
    attacks_detected = Counter('ml_attacks_detected', 'Total number of ML-detected attacks', registry=registry)
    attack_types = Counter('ml_attack_types', 'Number of attacks by type', ['attack_type'], registry=registry)
    flow_features = Histogram('flow_features', 'Distribution of flow features',
                              ['feature'], buckets=[10, 100, 1000, 10000, 100000], registry=registry)
    blocked_flows = Counter('flows_blocked', 'Number of flows blocked', registry=registry)
    current_blocked_flows = Gauge('current_blocked_flows', 'Currently blocked flows', registry=registry)
    top_source_ips = Counter('ml_top_source_ips', 'Attack count by source IP', ['src_ip'], registry=registry)
    top_destination_ips = Counter('ml_top_destination_ips', 'Attack count by destination IP', ['dst_ip'],
                                  registry=registry)
    active_malicious_flows = Gauge('active_malicious_flows', 'Number of currently active malicious flows',
                                   registry=registry)
    alert_handling_latency = Summary('ml_alert_handling_seconds', 'Latency of ML alert handling in seconds',
                                     registry=registry)

    def __init__(self, pushgateway_url='localhost:9001', loki_url="http://localhost:3100"):
        self.pushgateway_url = pushgateway_url
        self.loki_url = loki_url
        self.blocked_flows_dict = defaultdict(bool)
        self.active_flows = set()

    def handle_detection(self, flow_id, prediction, flow_data):
        """Handle a detected attack"""
        start_time = time.time()  # Start latency measurement

        # Extract necessary information
        src_ip = flow_data.get("Src IP", flow_id.split("_")[0] if "_" in flow_id else "unknown")
        dst_ip = flow_data.get("Dst IP", flow_id.split("_")[2] if "_" in flow_id else "unknown")
        src_port = flow_data.get("Src Port", "unknown")
        dst_port = flow_data.get("Dst Port", "unknown")
        attack_type = prediction

        # Update metrics
        self.attacks_detected.inc()
        self.attack_types.labels(attack_type).inc()
        self.top_source_ips.labels(src_ip).inc()
        self.top_destination_ips.labels(dst_ip).inc()

        # Record flow features for analysis
        for feature, value in flow_data.items():
            if isinstance(value, (int, float)):
                self.flow_features.labels(feature).observe(value)

        # Log to Loki
        message = f"ML Detection: {attack_type}"
        self.log_to_loki(message, src_ip, dst_ip, src_port, dst_port, flow_data)

        # Track the flow as blocked
        if flow_id not in self.blocked_flows_dict:
            print(f"Attack detected in flow: {flow_id}, type: {attack_type}")
            self.blocked_flows.inc()
            self.blocked_flows_dict[flow_id] = True
            self.current_blocked_flows.set(len(self.blocked_flows_dict))

        if flow_id not in self.active_flows:
            self.active_flows.add(flow_id)
            self.active_malicious_flows.inc()

        latency = time.time() - start_time
        self.alert_handling_latency.observe(latency)
        self.push_metrics()

        return True  # Return True to indicate the flow should be blocked

    def log_to_loki(self, message, src_ip, dst_ip, src_port, dst_port, flow_data):
        """Send log messages to Loki."""
        # Extract key flow metrics for logging
        flow_duration = flow_data.get("Flow Duration", "unknown")
        flow_bytes = flow_data.get("Flow Byts/s", "unknown")
        flow_packets = flow_data.get("Flow Pkts/s", "unknown")

        log_message = (f"{message}, src_ip: {src_ip}, src_port: {src_port}, "
                       f"dst_ip: {dst_ip}, dst_port: {dst_port}, "
                       f"duration: {flow_duration}, bytes/s: {flow_bytes}, pkts/s: {flow_packets}")

        log_entry = {
            "streams": [
                {
                    "stream": {
                        "job": "ml-alert-job",
                        "level": "alert",
                        "source": "ml-detector"
                    },
                    "values": [
                        [str(int(time.time() * 1e9)), log_message]
                    ]
                }
            ]
        }

        try:
            response = requests.post(f"{self.loki_url}/loki/api/v1/push", json=log_entry)
            if response.status_code == 204:
                print("ML alert successfully sent to Loki")
            else:
                print(f"Failed to send ML alert to Loki: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Error sending log to Loki: {e}")

    def end_detection(self, flow_id):
        """Mark a flow as no longer active."""
        if flow_id in self.active_flows:
            self.active_flows.remove(flow_id)
            self.active_malicious_flows.dec()
            print(f"Flow {flow_id} no longer active")

    def push_metrics(self):
        """Push metrics to Prometheus Pushgateway."""
        try:
            push_to_gateway(self.pushgateway_url, job='ml-attack-alert', registry=self.registry)
            print("ML metrics successfully pushed to Prometheus Pushgateway")
        except Exception as e:
            print(f"Failed to push metrics to Prometheus: {e}")


# For standalone testing
if __name__ == "__main__":
    alerter = AIAttackAlerter()
    test_flow = {
        "Flow ID": "192.168.1.100_12345_192.168.1.200_80_6",
        "Src IP": "192.168.1.100",
        "Dst IP": "192.168.1.200",
        "Src Port": 12345,
        "Dst Port": 80,
        "Protocol": 6,
        "Flow Duration": 5000,
        "Tot Fwd Pkts": 100,
        "Tot Bwd Pkts": 50,
        "TotLen Fwd Pkts": 15000,
        "TotLen Bwd Pkts": 5000,
        "Flow Byts/s": 4000,
        "Flow Pkts/s": 30
    }

    alerter.handle_detection(test_flow["Flow ID"], "DoS", test_flow)