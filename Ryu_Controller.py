from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import event
import secrets
from ryu.lib import hub
from ryu.lib.packet import packet, ipv6, icmpv6, ethernet, ether_types, tcp
from ryu.ofproto import ofproto_v1_3
import re


r2v_addr_map = {"fe80::200:ff:fe00:1":"::0","fe80::200:ff:fe00:2":"::0","fe80::200:ff:fe00:3":"::0","fe80::200:ff:fe00:4":"::0","fe80::200:ff:fe00:5":"::0","fe80::200:ff:fe00:6":"::0"}
dest_awaits_tcp_response = False
saved_src = "::99"

def neighbor_solicitation_multicast_addr(prefix,dst):
    
    last_pattern = r"(?<=:)([0-9a-fA-F]{,2})$"

    regex_result = ""

    match = re.search(last_pattern, dst)
    if match:
        regex_result = match.group(1)

    return(prefix+regex_result)

def get_real_ip_addr(virtual_addr):
    result = "::69"
    try:
        result = list(r2v_addr_map.keys())[list(r2v_addr_map.values()).index(virtual_addr)]
    except ValueError:
        print("virtual IP-Address '"+virtual_addr+"' not found in real to virtual address map")

    return(result)


def EmptyTable(datapath):
        '''
            Empties flow table of a switch!
            Remove Flow rules from switches
            Reference: https://sourceforge.net/p/ryu/mailman/message/32333352/
        '''
        ofProto=datapath.ofproto
        parser = datapath.ofproto_parser
        match=parser.OFPMatch()
        flow_mod=datapath.ofproto_parser.OFPFlowMod(datapath,0,0,0,ofProto.OFPFC_DELETE,0,0,1,ofProto.OFPCML_NO_BUFFER,ofProto.OFPP_ANY,ofProto.OFPG_ANY,0,match=match,instructions=[])
        datapath.send_msg(flow_mod)

def randomize_ipv6_addr():
    foundAddress = False
    ipv6_addr = "0000::"
    while not foundAddress:
        ipv6_prefix = "fe80::200:ff:fe00:"
        ipv6_postfix = secrets.token_hex(1)
        ipv6_addr = ipv6_prefix + str(ipv6_postfix)

        remove_zeros = r"(?<=:)([0]{,4})"

        ipv6_addr = re.sub(remove_zeros, '', ipv6_addr)
        
        if not ipv6_addr in r2v_addr_map or not ipv6_addr in r2v_addr_map.values():
            foundAddress = True 
    return ipv6_addr

def randomize_hosts(self):
    global r2v_addr_map
    for key in r2v_addr_map.keys():
            r2v_addr_map[key] = randomize_ipv6_addr() 
    print("\n")
    print("r2v_addr_map: ",r2v_addr_map)
    print("\n")
    for switch in self.datapaths:
        self.EmptyTable(switch)
        ofProto=switch.ofproto
        parser = switch.ofproto_parser
        match=parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofProto.OFPP_CONTROLLER,
                                    ofProto.OFPCML_NO_BUFFER)]
        self.add_flow(switch, 0, match, actions)

#Custom Event for time out
class EventMessage(event.EventBase):
    '''Create a custom event with a provided message'''
    def __init__(self, message):
        super(EventMessage, self).__init__()
        self.msg=message


#Main Application
class MovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [EventMessage]
    def start(self):
        self.send_event_to_observers(EventMessage("TIMEOUT"))
        super(MovingTargetDefense,self).start()
        self.threads.append(hub.spawn(self.TimerEventGen))
            
    def TimerEventGen(self):
        global r2v_addr_map
        while 1:
            if len(r2v_addr_map) == 0:
                print("please start the mininet topology")
            else: 
                self.send_event_to_observers(EventMessage("TIMEOUT"))
            hub.sleep(30)
            

    def __init__(self, *args, **kwargs):
        '''Constructor, used to initialize the member variables'''
        super(MovingTargetDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths=set()
        self.HostAttachments={}
        self.offset_of_mappings=0
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(EventMessage)
    def update_resources(self,ev):
        global r2v_addr_map

        randomize_hosts(self)


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
        global saved_src 
        global r2v_addr_map
        global dest_awaits_tcp_response

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

        ### --------------------------------------------------------------

       
        dpid = datapath.id
    
        pkt = packet.Packet(msg.data)
        ipv6_header = pkt.get_protocol(ipv6.ipv6)
        icmpv6_header = pkt.get_protocol(icmpv6.icmpv6)
        eth_header = pkt.get_protocol(ethernet.ethernet)
        tcp_header = pkt.get_protocol(tcp.tcp)

        actions = []
        print("ipv6_header.src: "+ipv6_header.src)
        print("ipv6_header.dst: "+ipv6_header.dst)
        """if not ipv6_header.src in r2v_addr_map and ipv6_header.dst == "ff02::16" and icmpv6_header.type_ == icmpv6.ND_ROUTER_SOLICIT:
            r2v_addr_map[ipv6_header.src] = randomize_ipv6_addr()
            print("\n")
            print("r2v_addr_map: ",r2v_addr_map)
            print("\n")"""
        
        
        if icmpv6_header  != None:
            if icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_SOLICIT: #and not neighbor_solicitation_multicast_addr("fe80::200:ff:fe00:",ipv6_header.dst) in r2v_addr_map:
                print("1")
                match=parser.OFPMatch(eth_type=0x86DD,
                                    in_port=in_port,
                                    ipv6_src=ipv6_header.src,
                                    ipv6_dst=neighbor_solicitation_multicast_addr("ff02::1:ff00:",ipv6_header.dst),
                                    icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT)
                actions.append(parser.OFPActionSetField(ipv6_dst=neighbor_solicitation_multicast_addr("ff02::1:ff00:",get_real_ip_addr(neighbor_solicitation_multicast_addr("fe80::200:ff:fe00:",ipv6_header.dst)))))
                actions.append(parser.OFPActionSetField(eth_dst=neighbor_solicitation_multicast_addr("33:33:ff:00:00:",get_real_ip_addr(neighbor_solicitation_multicast_addr("fe80::200:ff:fe00:",ipv6_header.dst)))))
                #actions.append(parser.OFPActionSetField(ipv6_nd_target=neighbor_solicitation_multicast_addr("00:00:00:00:00:",list(r2v_addr_map.values()).index(ipv6_header.src))))
                #actions.append(parser.OFPActionSetField(ipv6_dst=neighbor_solicitation_multicast_addr("ff02::1:ff00:",list(r2v_addr_map.values()).index(ipv6_header.dst))))
                #actions.append(parser.OFPActionSetField(ipv6_nd_target=neighbor_solicitation_multicast_addr("fe80::200:ff:fe00:",list(r2v_addr_map.values()).index(ipv6_header.dst))))
                actions.append(parser.OFPActionSetField(ipv6_nd_target=get_real_ip_addr(neighbor_solicitation_multicast_addr("fe80::200:ff:fe00:",ipv6_header.dst))))
                actions.append(parser.OFPActionSetField(ipv6_nd_sll=eth_header.src))
                self.add_flow(datapath, 1, match, actions)

            elif icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_ADVERT:
                print("2")
                match=parser.OFPMatch(eth_type=0x86DD,
                                    in_port=in_port,
                                    ipv6_src=ipv6_header.src,
                                    ipv6_dst=ipv6_header.dst,
                                    icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT)
                actions.append(parser.OFPActionSetField(ipv6_src=r2v_addr_map[ipv6_header.src]))
                actions.append(parser.OFPActionSetField(ipv6_nd_target=r2v_addr_map[ipv6_header.src]))
                self.add_flow(datapath, 1, match, actions)
            
            elif icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REQUEST:
                print("3")
                match=parser.OFPMatch(eth_type=0x86DD,
                                    in_port=in_port,
                                    ipv6_src=ipv6_header.src,
                                    ipv6_dst=ipv6_header.dst,
                                    icmpv6_type=icmpv6.ICMPV6_ECHO_REQUEST)
                actions.append(parser.OFPActionSetField(ipv6_dst=get_real_ip_addr(ipv6_header.dst)))
                self.add_flow(datapath, 1, match, actions)

            elif icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REPLY:
                print("4")
                match=parser.OFPMatch(eth_type=0x86DD,
                                        in_port=in_port,
                                        ipv6_src=ipv6_header.src,
                                        ipv6_dst=ipv6_header.dst,
                                        icmpv6_type=icmpv6.ICMPV6_ECHO_REPLY)
                actions.append(parser.OFPActionSetField(ipv6_src=r2v_addr_map[ipv6_header.src]))
                self.add_flow(datapath, 1, match, actions)

            elif ipv6_header.dst in r2v_addr_map and icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REQUEST:
                print("5")
                return
            
        if tcp_header != None:  
            if  tcp_header.has_flags(tcp.TCP_SYN) and ipv6_header.dst in r2v_addr_map.values():
                print("6")
                match=parser.OFPMatch(eth_type=0x86DD,
                                    in_port=in_port,
                                    ipv6_src=ipv6_header.src,
                                    ipv6_dst=ipv6_header.dst)
                actions.append(parser.OFPActionSetField(ipv6_dst=get_real_ip_addr(ipv6_header.dst)))
                actions.append(parser.OFPActionSetField(eth_src=eth_header.src))
                #self.add_flow(datapath, 1, match, actions)
                saved_src = ipv6_header.src

            elif tcp_header.has_flags(tcp.TCP_ACK, tcp.TCP_SYN):
                print("7")
                match=parser.OFPMatch(eth_type=0x86DD,
                                        in_port=in_port,
                                        ipv6_src=ipv6_header.src,
                                        ipv6_dst=ipv6_header.dst)
                actions.append(parser.OFPActionSetField(ipv6_src=r2v_addr_map[ipv6_header.src]))
                actions.append(parser.OFPActionSetField(ipv6_dst=saved_src))
                #self.add_flow(datapath, 1, match, actions)
                dest_awaits_tcp_response=True

            elif tcp_header.has_flags(tcp.TCP_PSH,tcp.TCP_ACK):
                print("TCP PSH, ACK found")
                if ipv6_header.dst in r2v_addr_map.values():
                    match=parser.OFPMatch(eth_type=0x86DD,
                                        in_port=in_port,
                                        ipv6_src=ipv6_header.src,
                                        ipv6_dst=ipv6_header.dst)
                    actions.append(parser.OFPActionSetField(ipv6_dst=get_real_ip_addr(ipv6_header.src)))
                    actions.append(parser.OFPActionSetField(eth_src=eth_header.src))
                
                elif ipv6_header.dst in r2v_addr_map:
                    match=parser.OFPMatch(eth_type=0x86DD,
                                        in_port=in_port,
                                        ipv6_src=ipv6_header.src,
                                        ipv6_dst=ipv6_header.dst)
                    actions.append(parser.OFPActionSetField(ipv6_src=r2v_addr_map[ipv6_header.src]))
                    actions.append(parser.OFPActionSetField(eth_src=eth_header.src))

            
            elif tcp_header.has_flags(tcp.TCP_ACK):
                print("TCP ACK found")
                if ipv6_header.dst in r2v_addr_map.values():
                    match=parser.OFPMatch(eth_type=0x86DD,
                                        in_port=in_port,
                                        ipv6_src=ipv6_header.src,
                                        ipv6_dst=ipv6_header.dst)
                    actions.append(parser.OFPActionSetField(ipv6_dst=get_real_ip_addr(ipv6_header.src)))
                    actions.append(parser.OFPActionSetField(eth_src=eth_header.src))
                
                elif ipv6_header.dst in r2v_addr_map:
                    match=parser.OFPMatch(eth_type=0x86DD,
                                        in_port=in_port,
                                        ipv6_src=ipv6_header.src,
                                        ipv6_dst=ipv6_header.dst)
                    actions.append(parser.OFPActionSetField(ipv6_src=r2v_addr_map[ipv6_header.src]))
                    actions.append(parser.OFPActionSetField(eth_src=eth_header.src))

                
                

            elif tcp_header.has_flags(tcp.TCP_PSH):
                print("TCP PSH found")

            
                
            
            

        ### --------------------------------------------------------------
        
        actions.append(parser.OFPActionOutput(out_port))

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)