from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import event
import random
import re
from ryu.lib import hub
from ryu.lib.packet import packet, ipv6, icmpv6, ethernet, tcp, udp
from mtd_switch import MtdSwitch



def neighbor_solicitation_multicast_addr(prefix, dst):

    last_pattern = r"(?<=:)([0-9a-fA-F]{,2})$"

    regex_result = ""

    match = re.search(last_pattern, dst)
    if match:
        regex_result = match.group(1)

    return (prefix+regex_result)

def randomize_ipv6_addr():
    ipv6_prefix = "fe80::200:ff:fe00:"
    ipv6_postfix = random.randbytes(1).hex()
    ipv6_addr = ipv6_prefix + str(ipv6_postfix)

    remove_zeros = r"(?<=:)([0]{,4})"

    ipv6_addr = re.sub(remove_zeros, '', ipv6_addr)

    return ipv6_addr


#Custom Event for time out
class EventMessage(event.EventBase):
    '''Create a custom event with a provided message'''
    def __init__(self, message):
        super(EventMessage, self).__init__()
        self.msg=message


#Main Application
class MovingTargetDefense(MtdSwitch):
    _EVENTS = [EventMessage]
    def __init__(self, *args, **kwargs):
        '''Constructor, used to initialize the member variables'''
        super(MovingTargetDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths=set()
        self.HostAttachments={}
        self.offset_of_mappings=0
        self.answer_to_ICMP_SOLICIT=False
        self.protected_hosts = ["00:00:00:00:00:01", "00:00:00:00:00:02"]
        self.addr_map = {}

    def start(self):
        super(MovingTargetDefense,self).start()
        self.threads.append(hub.spawn(self.TimerEventGen))
            
    def TimerEventGen(self):
        while 1:
            self.send_event_to_observers(EventMessage("TIMEOUT"))
            hub.sleep(30)

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

    def check_for_prot_hosts(self, eth_header, ipv6_header):
        if eth_header.src in self.protected_hosts:
            if not ipv6_header.src in self.addr_map and ipv6_header.src != "::":
                self.addr_map[ipv6_header.src] = randomize_ipv6_addr()
                self.print_address_pair(ipv6_header.src, self.addr_map[ipv6_header.src])

    def update_addr_map(self):
        for real_addr in self.addr_map.keys():
            self.addr_map[real_addr] = randomize_ipv6_addr()
            self.print_address_pair(real_addr, self.addr_map[real_addr])

    def print_address_pair(self, real_addr, virt_addr):
        print("real address: " + real_addr + " virtual address: " + virt_addr)

    def get_real_ip(self, virt_ip):
        if virt_ip in self.addr_map.values():
            return list(self.addr_map.keys())[list(self.addr_map.values()).index(virt_ip)]
        else:
            raise Exception("No real ip for virt ip: " + virt_ip)
        

    def handle_icmpv6_packets(self, icmpv6_header, ipv6_header, eth_header, actions, parser):
            if ipv6_header.src in self.addr_map.keys() or ipv6_header.src in self.addr_map.values()  or ipv6_header.dst in self.addr_map.values() or neighbor_solicitation_multicast_addr(
                            "fe80::200:ff:fe00:",ipv6_header.dst) in self.addr_map.values():
                if icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_SOLICIT and ipv6_header.src != "::" and eth_header.src not in self.protected_hosts:
                        print("1")
                        actions.append(parser.OFPActionSetField(ipv6_dst=neighbor_solicitation_multicast_addr(
                            "ff02::1:ff00:", self.get_real_ip(neighbor_solicitation_multicast_addr("fe80::200:ff:fe00:", ipv6_header.dst)))))
                        actions.append(parser.OFPActionSetField(eth_dst=neighbor_solicitation_multicast_addr(
                            "33:33:ff:00:00:", self.get_real_ip(neighbor_solicitation_multicast_addr("fe80::200:ff:fe00:", ipv6_header.dst)))))
                        actions.append(parser.OFPActionSetField(ipv6_nd_target=self.get_real_ip(
                            neighbor_solicitation_multicast_addr("fe80::200:ff:fe00:", ipv6_header.dst))))
                        actions.append(parser.OFPActionSetField(ipv6_nd_sll=eth_header.src))
                        self.answer_to_ICMP_SOLICIT=True
                        
                elif icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_ADVERT and not eth_header.src in self.protected_hosts or self.answer_to_ICMP_SOLICIT:
                        print("2")
                        actions.append(parser.OFPActionSetField(
                            ipv6_src=self.addr_map[ipv6_header.src]))
                        actions.append(parser.OFPActionSetField(
                            ipv6_nd_target=self.addr_map[ipv6_header.src]))
                        self.answer_to_ICMP_SOLICIT=False

                elif icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REQUEST and eth_header.src not in self.protected_hosts and ipv6_header.dst not in self.addr_map.keys():
                    print("3")
                    actions.append(parser.OFPActionSetField(
                        ipv6_dst=self.get_real_ip(ipv6_header.dst)))

                elif icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REPLY and eth_header.src in self.protected_hosts:
                    print("4")
                    actions.append(parser.OFPActionSetField(ipv6_src=self.addr_map[ipv6_header.src]))


                


    def handle_tcp_packets(self, tcp_header, ipv6_header, actions, parser):
        valid_tcp_packet=False
        if ipv6_header.src in self.addr_map.keys() or ipv6_header.src in self.addr_map.values() or ipv6_header.dst in self.addr_map.keys() or ipv6_header.dst in self.addr_map.values():
            if tcp_header.has_flags(tcp.TCP_SYN) and not tcp_header.has_flags(tcp.TCP_ACK) and ipv6_header.dst in self.addr_map.values():
                actions.append(parser.OFPActionSetField(ipv6_dst=self.get_real_ip(ipv6_header.dst)))
                valid_tcp_packet=True

            elif tcp_header.has_flags(tcp.TCP_ACK, tcp.TCP_SYN):
                actions.append(parser.OFPActionSetField(ipv6_src=self.addr_map[ipv6_header.src]))
                valid_tcp_packet=True
                
            elif tcp_header.has_flags(tcp.TCP_PSH,tcp.TCP_ACK):
                if ipv6_header.dst in self.addr_map.values():
                    actions.append(parser.OFPActionSetField(ipv6_dst=self.get_real_ip(ipv6_header.dst)))
                    valid_tcp_packet=True

                elif ipv6_header.src in self.addr_map.keys():
                    actions.append(parser.OFPActionSetField(ipv6_src=self.addr_map[ipv6_header.src]))
                    valid_tcp_packet=True

            elif tcp_header.has_flags(tcp.TCP_ACK):
                if ipv6_header.dst in self.addr_map.values():
                    actions.append(parser.OFPActionSetField(ipv6_dst=self.get_real_ip(ipv6_header.dst)))
                    valid_tcp_packet=True
                elif ipv6_header.src in self.addr_map.keys():
                    actions.append(parser.OFPActionSetField(ipv6_src=self.addr_map[ipv6_header.src]))
                    valid_tcp_packet=True
        return valid_tcp_packet


    def handle_udp_packets(self, ipv6_header, actions, parser):
        valid_udp_packet=False
        if ipv6_header.dst in self.addr_map.values():
                actions.append(parser.OFPActionSetField(ipv6_dst=self.get_real_ip(ipv6_header.dst)))
                valid_udp_packet=True

        elif ipv6_header.src in self.addr_map.keys():
            actions.append(parser.OFPActionSetField(ipv6_src=self.addr_map[ipv6_header.src]))
            valid_udp_packet=True

        return valid_udp_packet

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
    def update_resources(self,ev):
        self.update_addr_map()
        for switch in self.datapaths:
            self.EmptyTable(switch)
            ofProto=switch.ofproto
            parser = switch.ofproto_parser
            match=parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofProto.OFPP_CONTROLLER,
                                          ofProto.OFPCML_NO_BUFFER)]
            self.add_flow(switch, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        ### --------------------------------------------------------------

        pkt = packet.Packet(msg.data)
        eth_header = pkt.get_protocol(ethernet.ethernet)

        dst = eth_header.dst
        src = eth_header.src
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        pkt = packet.Packet(msg.data)
        ipv6_header = pkt.get_protocol(ipv6.ipv6)
        icmpv6_header = pkt.get_protocol(icmpv6.icmpv6)
        eth_header = pkt.get_protocol(ethernet.ethernet)
        tcp_header = pkt.get_protocol(tcp.tcp)
        udp_header = pkt.get_protocol(udp.udp)

        actions = []

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD


        self.check_for_prot_hosts(eth_header, ipv6_header)
        
        if icmpv6_header != None:
            if icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REQUEST and eth_header.src not in self.protected_hosts and ipv6_header.dst in self.addr_map.keys():
                return

            self.handle_icmpv6_packets(icmpv6_header, ipv6_header, eth_header, actions, parser)

        valid_tcp_packet = False
        if tcp_header != None:
            valid_tcp_packet = self.handle_tcp_packets(tcp_header, ipv6_header, actions, parser)
            
        valid_udp_packet = False
        if udp_header != None:
            valid_udp_packet = self.handle_udp_packets(ipv6_header, actions, parser)

        actions.append(parser.OFPActionOutput(out_port))

        if valid_tcp_packet or valid_udp_packet:
            match=parser.OFPMatch(eth_type=0x86DD,
                                        in_port=in_port,
                                        ipv6_src=ipv6_header.src,
                                        ipv6_dst=ipv6_header.dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)