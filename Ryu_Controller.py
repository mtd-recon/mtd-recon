from ryu.controller import ofp_event
from ryu.controller.handler import  MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import event
import random
import re
from ryu.lib import hub
from ryu.lib.packet import packet, ipv6, icmpv6, ethernet
from mtd_switch import MtdSwitch, add_flow, get_out_port, get_mtd_switch_actions



def neighbor_solicitation_multicast_addr(dst):
    
    last_pattern = r"(?<=:)([0-9a-fA-F]{,2})$"

    last = ""

    match = re.search(last_pattern, dst)
    if match:
        last = match.group(1)

    return("ff02::1:ff00:"+last)

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
    ipv6_prefix = "fe80::200:ff:fe00:"
    ipv6_postfix = random.randbytes(1).hex()
    ipv6_addr = ipv6_prefix + str(ipv6_postfix)
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

        self.virt_addr = "0000::"
        self.real_addr = "0000::"
        self.protected_hosts = ["00:00:00:00:00:01", "00:00:00:00:00:02"]
        self.addr_map = {}

    def start(self):
        self.send_event_to_observers(EventMessage("TIMEOUT"))
        super(MovingTargetDefense,self).start()
        self.threads.append(hub.spawn(self.TimerEventGen))
            
    def TimerEventGen(self):
        while 1:
            self.send_event_to_observers(EventMessage("TIMEOUT"))
            hub.sleep(30)

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

        actions = []

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        ### --------------------------------------------------------------
    
        self.check_for_prot_hosts(eth_header, ipv6_header)
        

        if  ipv6_header.dst == neighbor_solicitation_multicast_addr(self.virt_addr) and icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_SOLICIT:
            print("1")
            match=parser.OFPMatch(eth_type=0x86DD,
                                  in_port=in_port,
                                  ipv6_src=ipv6_header.src,
                                  ipv6_dst=neighbor_solicitation_multicast_addr(self.virt_addr),
                                  icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT)
            actions.append(parser.OFPActionSetField(ipv6_dst=neighbor_solicitation_multicast_addr(self.real_addr)))
            actions.append(parser.OFPActionSetField(ipv6_nd_target=self.real_addr))
            add_flow(datapath, 1, match, actions)


        elif ipv6_header.src == self.real_addr and icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_ADVERT:
            print("2")
            match=parser.OFPMatch(eth_type=0x86DD,
                                in_port=in_port,
                                ipv6_src=self.real_addr,
                                ipv6_dst=ipv6_header.dst,
                                icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT)
            actions.append(parser.OFPActionSetField(ipv6_src=self.virt_addr))
            actions.append(parser.OFPActionSetField(ipv6_nd_target=self.virt_addr))
            add_flow(datapath, 1, match, actions)
        
        elif ipv6_header.dst == self.virt_addr and icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REQUEST:
            print("3")
            match=parser.OFPMatch(eth_type=0x86DD,
                                  in_port=in_port,
                                  ipv6_src=ipv6_header.src,
                                  ipv6_dst=self.virt_addr,
                                  icmpv6_type=icmpv6.ICMPV6_ECHO_REQUEST)
            actions.append(parser.OFPActionSetField(ipv6_dst=self.real_addr))
            add_flow(datapath, 1, match, actions)

        elif ipv6_header.src == self.real_addr and icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REPLY:
            print("4")
            match=parser.OFPMatch(eth_type=0x86DD,
                                    in_port=in_port,
                                    ipv6_src=self.real_addr,
                                    ipv6_dst=ipv6_header.dst,
                                    icmpv6_type=icmpv6.ICMPV6_ECHO_REPLY)
            actions.append(parser.OFPActionSetField(ipv6_src=self.virt_addr))
            add_flow(datapath, 1, match, actions)

        elif ipv6_header.dst == self.real_addr and icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REQUEST:
            print("5")
            return
       


        ### --------------------------------------------------------------
        actions.append(parser.OFPActionOutput(out_port))

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    