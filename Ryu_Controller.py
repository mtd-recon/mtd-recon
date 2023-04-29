from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import event
import secrets
from ryu.lib import hub
from ryu.lib.packet import packet, ipv6, icmpv6, ethernet, ether_types, tcp, udp
from ryu.ofproto import ofproto_v1_3
import re

def neighbor_solicitation_multicast_addr(prefix, dst):

    last_pattern = r"(?<=:)([0-9a-fA-F]{,2})$"

    regex_result = ""

    match = re.search(last_pattern, dst)
    if match:
        regex_result = match.group(1)

    return (prefix+regex_result)


# Custom Event for time out
class EventMessage(event.EventBase):
    '''Create a custom event with a provided message'''

    def __init__(self, message):
        super(EventMessage, self).__init__()
        self.msg = message


# Main Application
class MovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [EventMessage]

    def __init__(self, *args, **kwargs):
        '''Constructor, used to initialize the member variables'''
        super(MovingTargetDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = set()
        self.HostAttachments = {}
        self.offset_of_mappings = 0
        self.r2v_addr_map = {"fe80::200:ff:fe00:1": "::0", 
                             "fe80::200:ff:fe00:2": "::0", 
                             "fe80::200:ff:fe00:3": "::0",
                             "fe80::200:ff:fe00:4": "::0", 
                             "fe80::200:ff:fe00:5": "::0", 
                             "fe80::200:ff:fe00:6": "::0"}
        self.datapaths=set()
        self.HostAttachments={}
        self.offset_of_mappings=0

        self.virt_addr = "0000::"
        self.real_addr = "0000::"
        self.protected_hosts = ["00:00:00:00:00:01", "00:00:00:00:00:02"]
        self.addr_map = {}

    def start(self):
        # self.send_event_to_observers(EventMessage("TIMEOUT"))
        super(MovingTargetDefense, self).start()
        self.threads.append(hub.spawn(self.TimerEventGen))

    def TimerEventGen(self):
        while 1:
            if len(self.r2v_addr_map) == 0:
                print("please start the mininet topology")
            else:
                self.send_event_to_observers(EventMessage("TIMEOUT"))
            hub.sleep(30)

    def randomize_ipv6_addr(self):
        foundAddress = False
        ipv6_addr = "0000::"
        while not foundAddress:
            ipv6_prefix = "fe80::200:ff:fe00:"
            ipv6_postfix = secrets.token_hex(1)
            ipv6_addr = ipv6_prefix + str(ipv6_postfix)

            remove_zeros = r"(?<=:)([0]{,4})"

            ipv6_addr = re.sub(remove_zeros, '', ipv6_addr)

            if not ipv6_addr in self.r2v_addr_map and not ipv6_addr in self.r2v_addr_map.values():
                foundAddress = True
        return ipv6_addr

    def get_real_ip_addr(self, virtual_addr):
        result = "::69"
        try:
            result = list(self.r2v_addr_map.keys())[
                        list(self.r2v_addr_map.values()).index(virtual_addr)]
        except ValueError:
            print("virtual IP-Address '"+virtual_addr +
                "' not found in real to virtual address map")

        return (result)

    def EmptyTable(self, datapath):
        '''
            Empties flow table of a switch!
            Remove Flow rules from switches
            Reference: https://sourceforge.net/p/ryu/mailman/message/32333352/
        '''
        ofProto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, 0, ofProto.OFPFC_DELETE, 0, 0, 1,
                                                      ofProto.OFPCML_NO_BUFFER, ofProto.OFPP_ANY, ofProto.OFPG_ANY, 0, match=match, instructions=[])
        datapath.send_msg(flow_mod)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handleSwitchFeatures(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths.add(datapath)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(EventMessage)
    def update_resources(self, ev):
        for key in self.r2v_addr_map.keys():
                self.r2v_addr_map[key] = self.randomize_ipv6_addr()
        print("\n")
        print("r2v_addr_map: ", self.r2v_addr_map)
        print("\n")
        
    def check_for_prot_hosts(self, eth_header, ipv6_header):
        if eth_header.src in self.protected_hosts:
            if not ipv6_header.src in self.addr_map:
                self.addr_map[ipv6_header.src] = randomize_ipv6_addr()
                self.print_address_pair(ipv6_header.src, self.addr_map[ipv6_header.src])

    def update_addr_map(self):
        for real_addr in self.addr_map:
            self.addr_map[real_addr] = randomize_ipv6_addr()
            self.print_address_pair(real_addr, self.addr_map[real_addr])

    def print_address_pair(self, real_addr, virt_addr):
        print("real address: " + real_addr + " virtual address: " + virt_addr)


    @set_ev_cls(EventMessage)
    def update_resources(self,ev):
        self.update_addr_map()
        for switch in self.datapaths:
            self.EmptyTable(switch)
            ofProto = switch.ofproto
            parser = switch.ofproto_parser
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofProto.OFPP_CONTROLLER,
                                        ofProto.OFPCML_NO_BUFFER)]
            self.add_flow(switch, 0, match, actions)

    def handle_icmpv6_packets(self, icmpv6_header, ipv6_header, eth_header, actions, parser):
        if icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_SOLICIT:
                if neighbor_solicitation_multicast_addr("fe80::200:ff:fe00:",ipv6_header.dst) in self.r2v_addr_map:
                    return
                actions.append(parser.OFPActionSetField(ipv6_dst=neighbor_solicitation_multicast_addr(
                    "ff02::1:ff00:", self.get_real_ip_addr(neighbor_solicitation_multicast_addr("fe80::200:ff:fe00:", ipv6_header.dst)))))
                actions.append(parser.OFPActionSetField(eth_dst=neighbor_solicitation_multicast_addr(
                    "33:33:ff:00:00:", self.get_real_ip_addr(neighbor_solicitation_multicast_addr("fe80::200:ff:fe00:", ipv6_header.dst)))))
                actions.append(parser.OFPActionSetField(ipv6_nd_target=self.get_real_ip_addr(
                    neighbor_solicitation_multicast_addr("fe80::200:ff:fe00:", ipv6_header.dst))))
                actions.append(parser.OFPActionSetField(ipv6_nd_sll=eth_header.src))
                    
        elif icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_ADVERT:
                actions.append(parser.OFPActionSetField(
                    ipv6_src=self.r2v_addr_map[ipv6_header.src]))
                actions.append(parser.OFPActionSetField(
                    ipv6_nd_target=self.r2v_addr_map[ipv6_header.src]))

        elif icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REQUEST:
            actions.append(parser.OFPActionSetField(
                ipv6_dst=self.get_real_ip_addr(ipv6_header.dst)))

        elif icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REPLY:
            actions.append(parser.OFPActionSetField(ipv6_src=self.r2v_addr_map[ipv6_header.src]))


    def handle_tcp_packets(self, tcp_header, ipv6_header, actions, parser):
        if tcp_header.has_flags(tcp.TCP_SYN) and not tcp_header.has_flags(tcp.TCP_ACK) and ipv6_header.dst in self.r2v_addr_map.values():
                actions.append(parser.OFPActionSetField(ipv6_dst=self.get_real_ip_addr(ipv6_header.dst)))

        elif tcp_header.has_flags(tcp.TCP_ACK, tcp.TCP_SYN):
            actions.append(parser.OFPActionSetField(
                ipv6_src=self.r2v_addr_map[ipv6_header.src]))
            
        elif tcp_header.has_flags(tcp.TCP_PSH,tcp.TCP_ACK):
            if ipv6_header.dst in self.r2v_addr_map.values():
                actions.append(parser.OFPActionSetField(ipv6_dst=self.get_real_ip_addr(ipv6_header.dst)))

            elif ipv6_header.dst in self.r2v_addr_map:
                actions.append(parser.OFPActionSetField(ipv6_src=self.r2v_addr_map[ipv6_header.src]))

        elif tcp_header.has_flags(tcp.TCP_ACK):
            if ipv6_header.dst in self.r2v_addr_map.values():
                actions.append(parser.OFPActionSetField(ipv6_dst=self.get_real_ip_addr(ipv6_header.dst)))

            elif ipv6_header.dst in self.r2v_addr_map:
                actions.append(parser.OFPActionSetField(ipv6_src=self.r2v_addr_map[ipv6_header.src]))


    def handle_udp_packets(self, ipv6_header, actions, parser):
        if ipv6_header.dst in self.r2v_addr_map.values():
                actions.append(parser.OFPActionSetField(ipv6_dst=self.get_real_ip_addr(ipv6_header.dst)))

        elif ipv6_header.dst in self.r2v_addr_map:
            actions.append(parser.OFPActionSetField(ipv6_src=self.r2v_addr_map[ipv6_header.src]))


    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=None):
        '''
            Adds flow rules to the switch
            Reference: Simple_Switch
            http://ryu.readthedocs.io/en/latest/writing_ryu_app.html
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            if hard_timeout == None:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=hard_timeout)
        else:
            if hard_timeout == None:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, hard_timeout=hard_timeout)
        datapath.send_msg(mod)
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handlePacketInEvents(self, ev):

        # If you hit this you might want to increase
        # the "miss_send_length" of your switch

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        # ignore lldp packet
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # --------------------------------------------------------------

        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        ipv6_header = pkt.get_protocol(ipv6.ipv6)
        icmpv6_header = pkt.get_protocol(icmpv6.icmpv6)
        eth_header = pkt.get_protocol(ethernet.ethernet)
        tcp_header = pkt.get_protocol(tcp.tcp)
        udp_header = pkt.get_protocol(udp.udp)

        actions = []

        if icmpv6_header != None:
            self.handle_icmpv6_packets(icmpv6_header, ipv6_header, eth_header, actions, parser)

        elif tcp_header != None:
            self.handle_tcp_packets(tcp_header, ipv6_header, actions, parser)
            
        if udp_header != None:
            self.handle_udp_packets(ipv6_header, actions, parser)   

        actions.append(parser.OFPActionOutput(out_port))

        match=parser.OFPMatch(eth_type=0x86DD,
                                        in_port=in_port,
                                        ipv6_src=ipv6_header.src,
                                        ipv6_dst=ipv6_header.dst,)
        self.add_flow(datapath, 1, match, actions)
            

        ### --------------------------------------------------------------
        


        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
