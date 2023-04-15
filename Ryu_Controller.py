from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import event
import random
from ryu.lib import hub
from ryu.lib.packet import packet, ipv6, icmpv6, ethernet, ether_types
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet.in_proto import IPPROTO_ICMPV6
import re

virt_addr = "0000::"
real_addr = "0000::"

def neighbor_advertisement_multicast_addr(dst):
    
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
class MovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [EventMessage]
    def start(self):
        self.send_event_to_observers(EventMessage("TIMEOUT"))
        super(MovingTargetDefense,self).start()
        self.threads.append(hub.spawn(self.TimerEventGen))
            
    def TimerEventGen(self):
        while 1:
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
        global virt_addr
        virt_addr = randomize_ipv6_addr()
        print("virt_addr: ",virt_addr)
        for switch in self.datapaths:
            self.EmptyTable(switch)
            ofProto=switch.ofproto
            parser = switch.ofproto_parser
            match=parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofProto.OFPP_CONTROLLER,
                                          ofProto.OFPCML_NO_BUFFER)]
            self.add_flow(switch, 0, match, actions)


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
        global real_addr
        global virt_addr
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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

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

        actions = []

        if eth_header.src == "00:00:00:00:00:01":
            if not ipv6_header.src == real_addr:
                real_addr = ipv6_header.src
                print("real_addr: ",real_addr)
                print("virt_addr: ",virt_addr)

        if ipv6_header.src == "fe80::200:ff:fe00:2" and ipv6_header.dst == neighbor_advertisement_multicast_addr(virt_addr) and icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_SOLICIT:
            print("1")
            match=parser.OFPMatch(eth_type=0x86DD,
                                  in_port=in_port,
                                  ipv6_src="fe80::200:ff:fe00:2",
                                  ipv6_dst=neighbor_advertisement_multicast_addr(virt_addr),
                                  icmpv6_type=icmpv6.ND_NEIGHBOR_SOLICIT)
            actions.append(parser.OFPActionSetField(ipv6_dst=neighbor_advertisement_multicast_addr(real_addr)))
            actions.append(parser.OFPActionSetField(eth_dst="33:33:ff:00:00:01"))
            actions.append(parser.OFPActionSetField(ipv6_nd_target=real_addr))
            actions.append(parser.OFPActionSetField(ipv6_nd_sll="00:00:00:00:00:02"))
            self.add_flow(datapath, 1, match, actions)


        elif ipv6_header.src == real_addr and ipv6_header.dst == "fe80::200:ff:fe00:2" and icmpv6_header.type_ == icmpv6.ND_NEIGHBOR_ADVERT:
            print("2")
            match=parser.OFPMatch(eth_type=0x86DD,
                                in_port=in_port,
                                ipv6_src=real_addr,
                                ipv6_dst="fe80::200:ff:fe00:2",
                                icmpv6_type=icmpv6.ND_NEIGHBOR_ADVERT)
            actions.append(parser.OFPActionSetField(ipv6_src=virt_addr))
            actions.append(parser.OFPActionSetField(ipv6_nd_target=virt_addr))
            self.add_flow(datapath, 1, match, actions)
        
        elif ipv6_header.src == "fe80::200:ff:fe00:2" and ipv6_header.dst == virt_addr and icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REQUEST:
            print("3")
            match=parser.OFPMatch(eth_type=0x86DD,
                                  in_port=in_port,
                                  ipv6_src="fe80::200:ff:fe00:2",
                                  ipv6_dst=virt_addr,
                                  icmpv6_type=icmpv6.ICMPV6_ECHO_REQUEST)
            actions.append(parser.OFPActionSetField(ipv6_dst=real_addr))
            self.add_flow(datapath, 1, match, actions)

        elif ipv6_header.src == real_addr and ipv6_header.dst == "fe80::200:ff:fe00:2" and icmpv6_header.type_ == icmpv6.ICMPV6_ECHO_REPLY:
            print("4")
            match=parser.OFPMatch(eth_type=0x86DD,
                                    in_port=in_port,
                                    ipv6_src=real_addr,
                                    ipv6_dst="fe80::200:ff:fe00:2",
                                    icmpv6_type=icmpv6.ICMPV6_ECHO_REPLY)
            actions.append(parser.OFPActionSetField(ipv6_src=virt_addr))
            self.add_flow(datapath, 1, match, actions)


        ### --------------------------------------------------------------
        actions.append(parser.OFPActionOutput(out_port))

        # install a flow to avoid packet_in next time
        """if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)"""
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)