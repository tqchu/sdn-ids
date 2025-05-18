from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls, MAIN_DISPATCHER
from ryu.lib.packet import ethernet, packet, ether_types, ipv4, ipv6, tcp, udp, icmp
from ryu.ofproto import ofproto_v1_3

import pydevd_pycharm

pydevd_pycharm.settrace(
    'localhost',             # PyCharm host
    port=5678,               # match the port in your PyCharm config
    stdoutToServer=True,
    stderrToServer=True,
    suspend=False,           # or True if you want execution to pause at start
    patch_multiprocessing=True
)

class TrafficLogger(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrafficLogger, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]


        self.add_flow(datapath, 0, match, actions)

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
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        eth_src = eth.src
        eth_dst = eth.dst
        ethertype = eth.ethertype

        pkt_size = len(msg.data)

        ip_src = ip_dst = protocol = src_port = dst_port = None

        if pkt_ipv4:
            ip_src = pkt_ipv4.src
            ip_dst = pkt_ipv4.dst
            protocol = pkt_ipv4.proto
        elif pkt_ipv6:
            ip_src = pkt_ipv6.src
            ip_dst = pkt_ipv6.dst
            protocol = pkt_ipv6.nxt

        if pkt_tcp:
            src_port = pkt_tcp.src_port
            dst_port = pkt_tcp.dst_port
        elif pkt_udp:
            src_port = pkt_udp.src_port
            dst_port = pkt_udp.dst_port

        proto_name = self.get_protocol_name(protocol)

        self.logger.info("packet: ETH(src=%s, dst=%s, type=%s), IP(src=%s, dst=%s), Proto=%s, SrcPort=%s, DstPort=%s, Size=%d bytes",
                         eth_src, eth_dst, hex(ethertype), ip_src, ip_dst, proto_name, src_port, dst_port, pkt_size)

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @staticmethod
    def get_protocol_name(protocol):
        proto_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            58: 'ICMPv6'
        }
        return proto_map.get(protocol, 'OTHER')
