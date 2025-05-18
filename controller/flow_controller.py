import traceback
from datetime import datetime
import pickle
import time

import pandas as pd
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.lib import hub
from ryu.lib.packet import ethernet, packet, ipv4, tcp, udp
from ryu.ofproto import ofproto_v1_3

from controller.flow_extractor import FlowFeatures


class SDNIDSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNIDSController, self).__init__(*args, **kwargs)
        self.flows = {}  # Dictionary to track FlowFeatures by flow key
        self.datapaths = {}
        self.offset = 0
        self.current_len = 0
        with open(
                '/home/truongchu/Academic/Graduation_Thesis/Project/AI/detector/dataset/InSDN_DatasetCSV/mlp_model.pkl',
                'rb') as f:
            self.model = pickle.load(f)

        # self.monitor_thread = hub.spawn(self._monitor)

        with open('/home/truongchu/Academic/Graduation_Thesis/Project/AI/detector/dataset/InSDN_DatasetCSV/scaler.pkl',
                  'rb') as f:
            self.scaler = pickle.load(f)
        # s
        # (Model loading and logging will be shown in later sections)

    # def _monitor(self):
    #     while True:
    #         for dp in self.datapaths.values():
    #             self._request_stats(dp)
    #         hub.sleep(5)
    #
    #         self.flow_predict()

    # def _request_stats(self, datapath):
    #     self.logger.debug('send stats request: %016x', datapath.id)
    #     parser = datapath.ofproto_parser
    #
    #     req = parser.OFPFlowStatsRequest(datapath, match = parser.OFPMatch(eth_type=0x0800, ip_proto=1))
    #     datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    # @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    # def _flow_stats_reply_handler(self, ev):
    #
    #     file0 = open("PredictFlowStatsfile.csv", "a")
    #     # file0.write(
    #     #     'Flow Duration,Active Mean,Idle Mean,Tot Fwd Pkts,TotLen Fwd Pkts,Flow Pkts/s,Flow Byts/s\n')
    #     body = ev.msg.body
    #
    #     for stat in body:
    #         duration_mseconds = stat.duration_sec * 1e6
    #         try:
    #             packet_count_per_second = stat.packet_count / stat.duration_sec
    #         except:
    #             packet_count_per_second = 0
    #
    #         try:
    #             byte_count_per_second = stat.byte_count / stat.duration_sec
    #         except:
    #             byte_count_per_second = 0
    #
    #         # file0.write("{},{},{},{}, {},{},{},{},{},{},{},{},{}\n"
    #         #             .format(timestamp, ev.msg.datapath.id,
    #         #                     stat.duration_sec, stat.duration_nsec,
    #         #                     stat.idle_timeout, stat.hard_timeout,
    #         #                     stat.flags, stat.packet_count, stat.byte_count,
    #         #                     packet_count_per_second, packet_count_per_nsecond,
    #         #                     byte_count_per_second, byte_count_per_nsecond))
    #         file0.write("{},{},{},{}, {},{},{}\n"
    #                     .format(duration_mseconds, stat.hard_timeout,
    #                             stat.idle_timeout, stat.packet_count, stat.byte_count,
    #                             packet_count_per_second,
    #                             byte_count_per_second))
    #
    #     self.current_len = len(body)
    #
    #     file0.close()
        # (Here we can process the flow statistics as needed, e.g., logging or updating a database)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # 1) Fast-path ICMP: priority 10
        match_icmp = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
        actions_normal = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, priority=10, match=match_icmp, actions=actions_normal)

        # 2) Table-miss: priority 0 → controller
        match_all = parser.OFPMatch()
        actions_ctrl = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                               ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, priority=0, match=match_all, actions=actions_ctrl)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        ofproto = datapath.ofproto

        in_port = msg.match['in_port']

        # self._extract_flow(msg)
        # (At this point, we have updated the flow's feature stats. Next, we may perform detection or forwarding logic.)

        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _extract_flow(self, msg):
        start_time = time.time()

        # Parse the packet using Ryu's packet library
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == 0x88cc or eth.ethertype == 0x8942:
            # Ignore LLDP/ARP or controller-specific packets to avoid interference
            return  # (This filters out Link Layer Discovery or other control packets)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        # We only proceed if this is an IP packet (IPv4 in this example)
        if ip_pkt is None:
            return  # Not an IPv4 packet, ignore (could be IPv6 or ARP, etc.)
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        proto = ip_pkt.proto  # Protocol number (6 for TCP, 17 for UDP, etc.)
        # Get L4 ports and flags if TCP/UDP
        if tcp_pkt:
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
            tcp_flags = tcp_pkt.bits  # TCP flags (as an int bitmask)
            # tcp_win = tcp_pkt.window
            tcp_win = None
        elif udp_pkt:
            src_port = udp_pkt.src_port
            dst_port = udp_pkt.dst_port
            tcp_flags = None
            tcp_win = None
        else:
            # ICMP or other protocols – handle if needed
            src_port = 0
            dst_port = 0
            tcp_flags = None
            tcp_win = None
        # Define a flow key and its reverse (for lookup)
        flow_key = (src_ip, src_port, dst_ip, dst_port, proto)
        rev_key = (dst_ip, dst_port, src_ip, src_port, proto)
        now = time.time()
        # Lookup or create a FlowFeatures object for this flow
        if flow_key in self.flows:
            flow = self.flows[flow_key]
        elif rev_key in self.flows:
            flow = self.flows[rev_key]
        else:
            # New flow: create and store it (under both forward and reverse keys for quick lookup)
            flow = FlowFeatures(flow_id=flow_key, src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port,
                                protocol=self.get_protocol_name(proto), start_time=now)
            flow.forward_src = src_ip  # designate this packet's source as "forward" direction
            self.flows[flow_key] = flow
            self.flows[rev_key] = flow

        # Determine packet direction (fwd/bwd) relative to initial source
        direction = 'fwd' if src_ip == flow.forward_src else 'bwd'
        # Calculate packet length (we use total length of packet data)
        pkt_len = len(msg.data)  # length in bytes of the entire packet (Ethernet frame)
        # Update flow features with this packet's info
        flow.update(direction, pkt_len, tcp_flags, now, tcp_win)

        self.logger.info("Flow features updated: %s", flow.get_features())
        # features = {
        #     "Src Port": 38694,
        #     "Dst Port": 4444,
        #     "Flow Duration": 269709,
        #     "Tot Fwd Pkts": 4,
        #     "Tot Bwd Pkts": 5,
        #     "TotLen Fwd Pkts": 48,
        #     "TotLen Bwd Pkts": 23,
        #     "Fwd Pkt Len Max": 30,
        #     "Fwd Pkt Len Min": 0,
        #     "Fwd Pkt Len Mean": 12,
        #     "Fwd Pkt Len Std": 14.69693846,
        #     "Bwd Pkt Len Max": 23,
        #     "Bwd Pkt Len Min": 0,
        #     "Bwd Pkt Len Mean": 4.6,
        #     "Bwd Pkt Len Std": 10.2859127,
        #     "Flow Byts/s": 263.2466844,
        #     "Flow Pkts/s": 33.36929802,
        # }

        # features_col = ["Src Port",
        #                 "Dst Port",
        #                 # "Protocol",
        #                 "Flow Duration",
        #                 "Tot Fwd Pkts",
        #                 "Tot Bwd Pkts",
        #                 "TotLen Fwd Pkts",
        #                 "TotLen Bwd Pkts",
        #                 "Fwd Pkt Len Max",
        #                 "Fwd Pkt Len Min",
        #                 "Fwd Pkt Len Mean",
        #                 "Fwd Pkt Len Std",
        #                 "Bwd Pkt Len Max",
        #                 "Bwd Pkt Len Min",
        #                 "Bwd Pkt Len Mean",
        #                 "Bwd Pkt Len Std",
        #                 "Flow Byts/s",
        #                 "Flow Pkts/s"]
        #
        # X = pd.DataFrame([features], columns=features_col)
        # X = self.scaler.transform(X)
        # y = self.model.predict(X)
        #
        # self.logger.info("Prediction %s", y)
        #
        # if y != 'Normal':
        #     self.logger.error("Attack Detected: %s", y)

        self.logger.info("Processing duration, %s", time.time() - start_time)

    @staticmethod
    def get_protocol_name(protocol):
        proto_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            58: 'ICMPv6'
        }
        return proto_map.get(protocol, 'OTHER')

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')

            features_col = ["Flow Duration", "Active Mean", "Idle Mean", "Tot Fwd Pkts", "TotLen Fwd Pkts",
                            "Flow Pkts/s", "Flow Byts/s"]

            if self.current_len ==0:
                return

            self.logger.info("Current len %d", self.current_len)
            self.logger.info("Current offset %d", self.offset)

            next_offset = min(self.offset + 100, len(predict_flow_dataset))

            features = predict_flow_dataset[features_col].iloc[self.offset:next_offset]

            self.logger.info("X %s", features)

            X = self.scaler.transform(features)
            y = self.model.predict(X)

            self.logger.info("Prediction %s", y)

            for idx, yi in enumerate(y):
                if yi != 'Normal':
                    self.logger.error("Attack Detected: %s", yi)
                    file0 = open("AttackDetected.csv", "a")
                    xi = predict_flow_dataset.iloc[idx]

                    file0.write("{},{},{},{}, {},{},{},{}\n"
                                .format(xi["Flow Duration"], xi["Active Mean"],
                                        xi["Idle Mean"], xi["Tot Fwd Pkts"], xi["TotLen Fwd Pkts"],
                                        xi["Flow Pkts/s"], xi["Flow Byts/s"], yi))

            self.logger.info("------------------------------------------------------------------------------")
            self.offset = next_offset
        except Exception as e:
            self.logger.error("Error in flow prediction: %s", str(e))
            self.logger.error("Traceback: %s", traceback.format_exc())

            pass
