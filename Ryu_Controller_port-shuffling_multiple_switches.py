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
        self.r2v_port_map = {22: 0, 
                             443: 0, 
                             80: 0,
                             764: 0,
                             5201: 0}

    def start(self):
        # self.send_event_to_observers(EventMessage("TIMEOUT"))
        super(MovingTargetDefense, self).start()
        self.threads.append(hub.spawn(self.TimerEventGen))

    def TimerEventGen(self):
        while 1:
            if len(self.r2v_port_map) == 0:
                print("please start the mininet topology")
            else:
                self.send_event_to_observers(EventMessage("TIMEOUT"))
            hub.sleep(30)

    def randomize_port(self):
        foundPort = False
        result = "0"
        while not foundPort:
            result = secrets.SystemRandom().randrange(1, 65535)
            if not result in self.r2v_port_map and not result in self.r2v_port_map.values():
                foundPort = True
        return result

    def get_real_ip_addr(self, virtual_addr):
        result = "::69"
        try:
            result = list(self.r2v_addr_map.keys())[
                        list(self.r2v_addr_map.values()).index(virtual_addr)]
        except ValueError:
            print("virtual IP-Address '"+virtual_addr +
                "' not found in real to virtual address map")

        return (result)
    
    def get_real_port(self, virtual_port):
        result = "0"
        try:
            result = list(self.r2v_port_map.keys())[
                        list(self.r2v_port_map.values()).index(virtual_port)]
        except ValueError:
            print("virtual port '"+virtual_port +
                "' not found in real to virtual port map")

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
        for key in self.r2v_port_map.keys():
                self.r2v_port_map[key] = self.randomize_port()
        print("\n")
        print("r2v_addr_map: ", self.r2v_port_map)
        print("\n")
        for switch in self.datapaths:
            self.EmptyTable(switch)
            ofProto = switch.ofproto
            parser = switch.ofproto_parser
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofProto.OFPP_CONTROLLER,
                                        ofProto.OFPCML_NO_BUFFER)]
            self.add_flow(switch, 0, match, actions)

    def handle_icmpv6_packets(self, icmpv6_header, ipv6_header, eth_header, actions, parser, datapath):
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
                    
        elif icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_ADVERT and ipv6_header.src in self.r2v_addr_map and datapath.id == self.HostAttachments[ipv6_header.src]:
                actions.append(parser.OFPActionSetField(
                    ipv6_src=self.r2v_addr_map[ipv6_header.src]))
                actions.append(parser.OFPActionSetField(
                    ipv6_nd_target=self.r2v_addr_map[ipv6_header.src]))

        elif icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REQUEST and ipv6_header.src in self.r2v_addr_map and datapath.id == self.HostAttachments[ipv6_header.src]:
            actions.append(parser.OFPActionSetField(
                ipv6_dst=self.get_real_ip_addr(ipv6_header.dst)))

        elif icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REPLY:
            actions.append(parser.OFPActionSetField(ipv6_src=self.r2v_addr_map[ipv6_header.src]))


    def handle_tcp_packets(self, tcp_header, ipv6_header, actions, parser, datapath):
        
            if tcp_header.has_flags(tcp.TCP_SYN) and not tcp_header.has_flags(tcp.TCP_ACK) and tcp_header.dst_port in self.r2v_port_map.values():
                    actions.append(parser.OFPActionSetField(tcp_dst=self.get_real_port(tcp_header.dst_port)))

            elif tcp_header.has_flags(tcp.TCP_ACK, tcp.TCP_SYN) and datapath.id == self.HostAttachments[ipv6_header.src]:
                actions.append(parser.OFPActionSetField(tcp_src=self.r2v_port_map[tcp_header.src_port]))
                
            elif tcp_header.has_flags(tcp.TCP_PSH,tcp.TCP_ACK):
                if tcp_header.dst_port in self.r2v_port_map.values():
                    actions.append(parser.OFPActionSetField(tcp_dst=self.get_real_port(tcp_header.dst_port)))

                elif tcp_header.src_port in self.r2v_port_map.keys():
                    actions.append(parser.OFPActionSetField(tcp_src=self.r2v_port_map[tcp_header.src_port]))

            elif tcp_header.has_flags(tcp.TCP_ACK) and not tcp_header.has_flags(tcp.TCP_RST):
                if tcp_header.dst_port in self.r2v_port_map.values():
                    actions.append(parser.OFPActionSetField(tcp_dst=self.get_real_port(tcp_header.dst_port)))

                elif tcp_header.src_port in self.r2v_port_map.keys():
                    actions.append(parser.OFPActionSetField(tcp_src=self.r2v_port_map[tcp_header.src_port]))


    def handle_udp_packets(self, udp_header, actions, parser):
        if udp_header.dst_port in self.r2v_port_map.values():
                actions.append(parser.OFPActionSetField(udp_dst=self.get_real_port(udp_header.dst_port)))

        elif udp_header.src_port in self.r2v_port_map.keys():
            actions.append(parser.OFPActionSetField(udp_src=self.r2v_port_map[udp_header.src_port]))


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
        tcp_header = pkt.get_protocol(tcp.tcp)
        udp_header = pkt.get_protocol(udp.udp)

        actions = []

        """if icmpv6_header != None:
            self.handle_icmpv6_packets(icmpv6_header, ipv6_header, eth_header, actions, parser, datapath)"""
        

        if ipv6_header.src not in self.HostAttachments.keys():
                self.HostAttachments[ipv6_header.src]=datapath.id

        if tcp_header != None and (tcp_header.src_port in self.r2v_port_map.keys() or tcp_header.src_port in self.r2v_port_map.values() or tcp_header.dst_port in self.r2v_port_map.keys() or tcp_header.dst_port in self.r2v_port_map.values()):
            self.handle_tcp_packets(tcp_header, ipv6_header, actions, parser, datapath)
        
        if udp_header != None and (udp_header.src_port in self.r2v_port_map.keys() or udp_header.src_port in self.r2v_port_map.values() or udp_header.dst_port in self.r2v_port_map.keys() or udp_header.dst_port in self.r2v_port_map.values()):
            self.handle_udp_packets(udp_header, ipv6_header, actions, parser, datapath)  
            
        actions.append(parser.OFPActionOutput(out_port))

        ### --------------------------------------------------------------
        


        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

