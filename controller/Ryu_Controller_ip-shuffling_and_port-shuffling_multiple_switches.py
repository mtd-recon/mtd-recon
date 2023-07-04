from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import event
import random
import secrets
import re
from ryu.lib import hub
from ryu.lib.packet import packet, ipv6, icmpv6, ethernet, tcp, udp
from ryu.lib.packet.icmpv6 import nd_neighbor
from ryu.lib.packet.in_proto import IPPROTO_TCP
from mtd_switch import MtdSwitch


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
        self.saved_datapath_id=0
        self.protected_hosts = ["00:00:00:00:00:01",
                                "00:00:00:00:00:02"]
        self.r2v_port_map = {22: 0, 
                            443: 0, 
                            80: 0,
                            764: 0,
                            5201: 0}
        self.answer_to_ICMP_SOLICIT=False
        self.legit_TCP_SYN_ACK_MSG = False
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

    def randomize_ipv6_addr(self):
        nr_of_groups = 8
        ipv6_addr = "fe80::"
        byte_group_delimiter = ":"
        
        for i in range(nr_of_groups-4):
            two_byte_group = random.randbytes(2).hex()
            if i == nr_of_groups - 5:
                ipv6_addr = ipv6_addr + str(two_byte_group)
            else:
                ipv6_addr = ipv6_addr + str(two_byte_group) + byte_group_delimiter

        remove_leading_zeros = r"(?<=:)([0]{,4})"

        ipv6_addr = re.sub(remove_leading_zeros, '', ipv6_addr)

        return ipv6_addr

    def randomize_port(self):
        foundPort = False
        result = "0"
        while not foundPort:
            result = secrets.SystemRandom().randrange(1, 65535)
            if not result in self.r2v_port_map.keys() and not result in self.r2v_port_map.values():
                foundPort = True
        return result
    
    def neighbor_solicitation_multicast_addr(self, prefix, dst):
        last_pattern = r"(?<=:)([0-9a-fA-F]{,4})$"
        regex_result = ""
        match = re.search(last_pattern, dst)
        if match:
            regex_result = match.group(1)
        return (prefix+regex_result)

    def create_tcp_RST_ACK_packet(self,datapath,src_ip,src_mac,src_port,dst_ip,dst_mac,dst_port,ack,out_port):
        # Define the Ethernet, IPv6 and TCP headers                                 
        eth_h = ethernet.ethernet(src=src_mac, dst=dst_mac, ethertype=0x86DD)
        ipv6_h = ipv6.ipv6(src=src_ip, dst=dst_ip, nxt=IPPROTO_TCP, hop_limit=64)
        tcp_h = tcp.tcp(src_port=src_port, dst_port=dst_port, bits=0b10100, seq=0, ack=ack, offset=5, window_size=0, option=None)

        # Create the OpenFlow packet_out message
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out_packet = packet.Packet()
        out_packet.add_protocol(eth_h)
        out_packet.add_protocol(ipv6_h)
        out_packet.add_protocol(tcp_h)
        out_packet.serialize()
        packet_out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=out_packet.data)
        # Send the packet_out message
        datapath.send_msg(packet_out)

    def tcp_ip_shuffling(self, tcp_header, ipv6_header, actions, parser, datapath):
        if datapath.id == self.HostAttachments[ipv6_header.src] and (ipv6_header.src in self.addr_map.keys() or ipv6_header.src in self.addr_map.values() or ipv6_header.dst in self.addr_map.keys() or ipv6_header.dst in self.addr_map.values()):
            if tcp_header.has_flags(tcp.TCP_SYN) and not tcp_header.has_flags(tcp.TCP_ACK) and ipv6_header.dst in self.addr_map.values():
                actions.append(parser.OFPActionSetField(ipv6_dst=self.get_real_ip(ipv6_header.dst)))

            elif tcp_header.has_flags(tcp.TCP_ACK, tcp.TCP_SYN) and ipv6_header.src in self.addr_map.keys() and datapath.id == self.HostAttachments[ipv6_header.src]:
                actions.append(parser.OFPActionSetField(ipv6_src=self.addr_map[ipv6_header.src]))
                
            elif tcp_header.has_flags(tcp.TCP_PSH,tcp.TCP_ACK):
                if ipv6_header.dst in self.addr_map.values():
                    actions.append(parser.OFPActionSetField(ipv6_dst=self.get_real_ip(ipv6_header.dst)))

                elif ipv6_header.src in self.addr_map.keys():
                    actions.append(parser.OFPActionSetField(ipv6_src=self.addr_map[ipv6_header.src]))

            elif tcp_header.has_flags(tcp.TCP_ACK):
                if ipv6_header.dst in self.addr_map.values():
                    actions.append(parser.OFPActionSetField(ipv6_dst=self.get_real_ip(ipv6_header.dst)))

                elif ipv6_header.src in self.addr_map.keys():
                    actions.append(parser.OFPActionSetField(ipv6_src=self.addr_map[ipv6_header.src]))

    def udp_ip_shuffling(self, ipv6_header, actions, parser):
        if ipv6_header.dst in self.addr_map.values():
            actions.append(parser.OFPActionSetField(ipv6_dst=self.get_real_ip(ipv6_header.dst)))

        elif ipv6_header.src in self.addr_map.keys():
            actions.append(parser.OFPActionSetField(ipv6_src=self.addr_map[ipv6_header.src]))


    def tcp_port_shuffling(self, tcp_header, ipv6_header, actions, parser, datapath):
        if tcp_header.has_flags(tcp.TCP_SYN) and not tcp_header.has_flags(tcp.TCP_ACK) and tcp_header.dst_port in self.r2v_port_map.values() and datapath.id == self.HostAttachments[ipv6_header.src]:
            actions.append(parser.OFPActionSetField(tcp_dst=self.get_real_port(tcp_header.dst_port)))
            self.legit_TCP_SYN_ACK_MSG=True

        elif tcp_header.has_flags(tcp.TCP_SYN, tcp.TCP_ACK) and tcp_header.src_port in self.r2v_port_map.keys() and datapath.id == self.HostAttachments[ipv6_header.src] and self.legit_TCP_SYN_ACK_MSG:
            actions.append(parser.OFPActionSetField(tcp_src=self.r2v_port_map[tcp_header.src_port]))
            self.legit_TCP_SYN_ACK_MSG=False

        elif tcp_header.has_flags(tcp.TCP_PSH,tcp.TCP_ACK) and datapath.id == self.HostAttachments[ipv6_header.src]:
            if tcp_header.dst_port in self.r2v_port_map.values():
                actions.append(parser.OFPActionSetField(tcp_dst=self.get_real_port(tcp_header.dst_port)))

            elif tcp_header.src_port in self.r2v_port_map.keys():
                actions.append(parser.OFPActionSetField(tcp_src=self.r2v_port_map[tcp_header.src_port]))

        elif tcp_header.has_flags(tcp.TCP_ACK) and not tcp_header.has_flags(tcp.TCP_RST) and not tcp_header.has_flags(tcp.TCP_SYN) and datapath.id == self.HostAttachments[ipv6_header.src]:
            if tcp_header.dst_port in self.r2v_port_map.values() and datapath.id == self.HostAttachments[ipv6_header.src]: #Kontrollieren !!
                actions.append(parser.OFPActionSetField(tcp_dst=self.get_real_port(tcp_header.dst_port)))

            elif tcp_header.src_port in self.r2v_port_map.keys() and datapath.id == self.HostAttachments[ipv6_header.src]: #Kontrollieren !!
                actions.append(parser.OFPActionSetField(tcp_src=self.r2v_port_map[tcp_header.src_port]))

    def udp_port_shuffling(self, udp_header, ipv6_header, actions, parser, datapath):
        if udp_header.dst_port in self.r2v_port_map.values() and datapath.id == self.HostAttachments[ipv6_header.src]:
            actions.append(parser.OFPActionSetField(udp_dst=self.get_real_port(udp_header.dst_port)))

        elif udp_header.src_port in self.r2v_port_map.keys() and datapath.id == self.HostAttachments[ipv6_header.src]:
            actions.append(parser.OFPActionSetField(udp_src=self.r2v_port_map[udp_header.src_port]))

    def check_for_prot_hosts(self, eth_header, ipv6_header):
        if eth_header.src in self.protected_hosts and ipv6_header.src not in self.addr_map.values() and ipv6_header.src not in self.addr_map.keys() and ipv6_header.src != "::":
            self.addr_map[ipv6_header.src] = self.randomize_ipv6_addr()
            self.print_address_pair(ipv6_header.src, self.addr_map[ipv6_header.src])

    def update_addr_map(self):
        for real_addr in self.addr_map.keys():
            self.addr_map[real_addr] = self.randomize_ipv6_addr()
            self.print_address_pair(real_addr, self.addr_map[real_addr])

    def update_port_map(self):
        for key in self.r2v_port_map.keys():
                self.r2v_port_map[key] = self.randomize_port()
                self.print_port_pair(key, self.r2v_port_map[key])
        

    def print_address_pair(self, real_addr, virt_addr):
        print("real address: " + real_addr + " virtual address: " + virt_addr)

    def print_port_pair(self, real_port, virt_port):
        print("real port: " + str(real_port) + " virtual port: " + str(virt_port))

    def get_real_ip(self, virt_ip):
        if virt_ip in self.addr_map.values():
            return list(self.addr_map.keys())[list(self.addr_map.values()).index(virt_ip)]
        else:
            raise Exception("No real ip for virt ip: " + virt_ip)

    def get_real_port(self, virtual_port):
        result = "0"
        try:
            result = list(self.r2v_port_map.keys())[
                        list(self.r2v_port_map.values()).index(virtual_port)]
        except ValueError:
            print("virtual port '"+virtual_port +
                "' not found in real to virtual port map")
        return result
        

    def handle_icmpv6_packets(self, icmpv6_header, ipv6_header, eth_header, actions, parser, datapath):
            if ipv6_header.src in self.addr_map.keys() or ipv6_header.src in self.addr_map.values() or (type(icmpv6_header.data) is nd_neighbor and icmpv6_header.data.dst in self.addr_map.values()) or ipv6_header.dst in self.addr_map.values():
                if icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_SOLICIT and icmpv6_header.data.dst in self.addr_map.values() and ipv6_header.src != "::":
                        actions.append(parser.OFPActionSetField(ipv6_dst=self.neighbor_solicitation_multicast_addr(
                            "ff02::1:ff00:", self.get_real_ip(icmpv6_header.data.dst))))
                        actions.append(parser.OFPActionSetField(eth_dst=self.neighbor_solicitation_multicast_addr(
                            "33:33:ff:00:00:", self.get_real_ip(icmpv6_header.data.dst))))
                        actions.append(parser.OFPActionSetField(ipv6_nd_target=self.get_real_ip(icmpv6_header.data.dst)))
                        actions.append(parser.OFPActionSetField(ipv6_nd_sll=eth_header.src))
                        self.answer_to_ICMP_SOLICIT=True
                        self.saved_datapath_id=datapath.id
                        
                elif icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_ADVERT and datapath.id == self.HostAttachments[ipv6_header.src] and self.answer_to_ICMP_SOLICIT:
                        actions.append(parser.OFPActionSetField(
                            ipv6_src=self.addr_map[ipv6_header.src]))
                        actions.append(parser.OFPActionSetField(
                            ipv6_nd_target=self.addr_map[ipv6_header.src]))
                        self.answer_to_ICMP_SOLICIT=False

                elif icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REQUEST and datapath.id == self.HostAttachments[ipv6_header.src] and ipv6_header.dst in self.addr_map.values():
                    actions.append(parser.OFPActionSetField(
                        ipv6_dst=self.get_real_ip(ipv6_header.dst)))

                elif icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REPLY and ipv6_header.src in self.addr_map.keys() and ipv6_header.src not in self.addr_map.values():
                    actions.append(parser.OFPActionSetField(ipv6_src=self.addr_map[ipv6_header.src]))            


    def handle_tcp_packets(self, tcp_header, ipv6_header, actions, parser, datapath):
        self.tcp_ip_shuffling(tcp_header, ipv6_header, actions, parser, datapath)
        self.tcp_port_shuffling(tcp_header, ipv6_header, actions, parser, datapath)


    def handle_udp_packets(self, udp_header, ipv6_header, actions, parser, datapath):
        self.udp_ip_shuffling(ipv6_header, actions, parser)
        self.udp_port_shuffling(udp_header, ipv6_header, actions, parser, datapath)
        
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
        self.update_port_map()
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

        if ipv6_header.src not in self.HostAttachments.keys():
                self.HostAttachments[ipv6_header.src]=datapath.id
        
        if icmpv6_header != None:
        
            if icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REQUEST and ipv6_header.dst in self.addr_map.keys() and datapath.id == self.HostAttachments[ipv6_header.src]: 
                return
    
            elif icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_ADVERT and not self.answer_to_ICMP_SOLICIT and ipv6_header.src in self.addr_map.keys() and datapath.id == self.HostAttachments[ipv6_header.dst] and (type(icmpv6_header.data) is nd_neighbor and icmpv6_header.data.option != None):
                return

            # for destination unreachable (port unreachable) messages of nmap udp port scans (see wireshark). Also used so that traceroute6 dont work on the real ip address of a protected host
            elif icmpv6_header.type_ == icmpv6.ICMPV6_DST_UNREACH and ipv6_header.src in self.addr_map.keys() and datapath.id == self.HostAttachments[ipv6_header.src]:
                return

            self.handle_icmpv6_packets(icmpv6_header, ipv6_header, eth_header, actions, parser, datapath)

        if tcp_header != None:
            #check if dst port is not protected, if it is, create a TCP RST ACK packet and send as answer of the packet and drop the old answer 
            if not self.legit_TCP_SYN_ACK_MSG and tcp_header.has_flags(tcp.TCP_ACK, tcp.TCP_SYN) and tcp_header.src_port in self.r2v_port_map.keys() and datapath.id == self.HostAttachments[ipv6_header.src]:
                ipv6_header_src = ipv6_header.src
                if ipv6_header.src in self.addr_map.keys():
                    ipv6_header_src = self.addr_map[ipv6_header.src]
                self.create_tcp_RST_ACK_packet(datapath,ipv6_header_src,eth_header.src,tcp_header.src_port,ipv6_header.dst,eth_header.dst,tcp_header.dst_port,tcp_header.ack,out_port)
                return
            self.handle_tcp_packets(tcp_header, ipv6_header, actions, parser, datapath)
            
        if udp_header != None:
            self.handle_udp_packets(udp_header, ipv6_header, actions, parser, datapath)

        actions.append(parser.OFPActionOutput(out_port))

        if icmpv6_header != None and (icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REQUEST or icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REPLY): 
            # ip_proto=58 => 58 = ICMPv6
            match = parser.OFPMatch(eth_type=0x86DD, in_port=in_port, eth_dst=dst, ipv6_dst=ipv6_header.dst, ipv6_src=ipv6_header.src, ip_proto=58, icmpv6_type=icmpv6_header.type_)
            self.add_flow(datapath, 1, match, actions)

        if tcp_header != None: 
            # ip_proto=6 => 6 = TCP
            match = parser.OFPMatch(eth_type=0x86DD, in_port=in_port, tcp_src=tcp_header.src_port, tcp_dst=tcp_header.dst_port, eth_dst=dst, ip_proto=6)
            self.add_flow(datapath, 1, match, actions)

        if udp_header != None:
            # ip_proto=17 => 17 = UDP
            match = parser.OFPMatch(eth_type=0x86DD, in_port=in_port, udp_src=udp_header.src_port, udp_dst=udp_header.dst_port, eth_dst=dst, ip_proto=17)

            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)