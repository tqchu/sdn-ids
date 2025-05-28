# blocker.py
import os

import requests

ADD_ENDPOINT = f"http://{os.getenv('CONTROLLER_HOST','127.0.0.1')}:8082/stats/flowentry/add"  # Ryu default
DELETE_ENDPOINT = "http://127.0.0.1:8082/stats/flowentry/delete_strict"  # Ryu default
DPID     = os.getenv("DPID",345052807170)            # bridge datapath-id
TABLE_ID = 0            # table where you drop; adjust if using multi-table
DROP_PRIORITY = 600     # higher than normal-allow rules

def block_flow(flow_tuple, proto):
    """
    flow_tuple → (src_ip, dst_ip, src_port, dst_port)
    proto      → 6 TCP, 17 UDP, 1 ICMP …
    """
    src_ip, dst_ip, sport, dport = flow_tuple
    match = {
        "eth_type": 0x0800,         # IPv4; use 0x86DD for IPv6
        "ipv4_src": src_ip,
        "ipv4_dst": dst_ip,
        "ip_proto": proto
    }

    if proto == 6:   # TCP
        match["tcp_src"] = sport
        match["tcp_dst"] = dport
    elif proto == 17:  # UDP
        match["udp_src"] = sport
        match["udp_dst"] = dport

    payload = {
        "dpid":      DPID,
        "priority":  DROP_PRIORITY,
        "table_id":  TABLE_ID,
        "match":     match,
        "actions": []              # empty actions = DROP
    }
    resp = requests.post(ADD_ENDPOINT, json=payload, timeout=1)

    resp.raise_for_status()

def unblock_flow(flow_tuple, proto):
    """
    flow_tuple → (src_ip, dst_ip, src_port, dst_port)
    proto      → 6 TCP, 17 UDP, 1 ICMP …
    """
    src_ip, dst_ip, sport, dport = flow_tuple
    match = {
        "eth_type": 0x0800,         # IPv4; use 0x86DD for IPv6
        "ipv4_src": src_ip,
        "ipv4_dst": dst_ip,
        "ip_proto": proto
    }

    if proto == 6:   # TCP
        match["tcp_src"] = sport
        match["tcp_dst"] = dport
    elif proto == 17:  # UDP
        match["udp_src"] = sport
        match["udp_dst"] = dport

    payload = {
        "dpid":      DPID,
        "priority":  DROP_PRIORITY,
        "table_id":  TABLE_ID,
        "match":     match,
        "actions": []              # empty actions = DROP
    }

    resp = requests.post(DELETE_ENDPOINT, json=payload, timeout=1)

    resp.raise_for_status()

if __name__=="__main__":
    unblock_flow(("10.50.50.1", "10.50.50.128", 58000, 32), 6)

