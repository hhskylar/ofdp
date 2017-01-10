# -*- coding: utf-8 -*-
#last updata:2016/12/13
#author:Eason Chang
#OFDP

#-----------------import libary------------------------
import logging
import six
import struct
import time
import json
import math

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
#from ryu.controller import dpset
#from ryu.topology import api
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub

from ryu.exception import RyuException
from ryu.lib import addrconv, hub
from ryu.lib.mac import DONTCARE_STR
from ryu.lib.dpid import dpid_to_str, str_to_dpid
from ryu.lib.port_no import port_no_to_str
from ryu.lib.packet import lldp
from ryu.lib.packet import arp, ipv4, ipv6
from ryu.ofproto.ether import ETH_TYPE_LLDP
from ryu.ofproto import nx_match
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.lib import hub
# from ryu.topology import event, switches
# from ryu.topology.api import get_switch, get_link



class LLDPPacket(object):
    # make a LLDP packet for link discovery.
    '''
    instead of sending LLDP to every port
    just send LLDP to every switch
    '''

    CHASSIS_ID_PREFIX = 'dpid:'
    CHASSIS_ID_PREFIX_LEN = len(CHASSIS_ID_PREFIX)
    CHASSIS_ID_FMT = CHASSIS_ID_PREFIX + '%s'

    PORT_ID_STR = '!I'      # uint32_t
    PORT_ID_SIZE = 4

    class LLDPUnknownFormat(RyuException):
        message = '%(msg)s'

    @staticmethod
    def lldp_packet(dpid, port_no, dl_addr, ttl):
        pkt = packet.Packet()

        dst = lldp.LLDP_MAC_NEAREST_BRIDGE
        src = dl_addr
        ethertype = ETH_TYPE_LLDP
        eth_pkt = ethernet.ethernet(dst, src, ethertype)
        pkt.add_protocol(eth_pkt)

        tlv_chassis_id = lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
            chassis_id=(LLDPPacket.CHASSIS_ID_FMT %
                        dpid_to_str(dpid)).encode('ascii'))

        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_PORT_COMPONENT,
                                  port_id=struct.pack(
                                      LLDPPacket.PORT_ID_STR,
                                      port_no))

        tlv_ttl = lldp.TTL(ttl=ttl)
        tlv_end = lldp.End()

        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
        lldp_pkt = lldp.lldp(tlvs)
        pkt.add_protocol(lldp_pkt)

        pkt.serialize()
        return pkt.data

    @staticmethod
    def lldp_parse(data):
        pkt = packet.Packet(data)
        i = iter(pkt)
        eth_pkt = six.next(i)
        assert type(eth_pkt) == ethernet.ethernet

        lldp_pkt = six.next(i)
        if type(lldp_pkt) != lldp.lldp:
            raise LLDPPacket.LLDPUnknownFormat()

        tlv_chassis_id = lldp_pkt.tlvs[0]
        if tlv_chassis_id.subtype != lldp.ChassisID.SUB_LOCALLY_ASSIGNED:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id subtype %d' % tlv_chassis_id.subtype)
        chassis_id = tlv_chassis_id.chassis_id
        if not chassis_id.startswith(LLDPPacket.CHASSIS_ID_PREFIX):
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id format %s' % chassis_id)
        src_dpid = str_to_dpid(chassis_id[LLDPPacket.CHASSIS_ID_PREFIX_LEN:])
        return src_dpid


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]  #OpenFlow 1.3v

    #init function
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.datapaths_id = []
        self.lldp_pkt_cnt = 0
        self.traffic_cnt = 0
        self.packet_out_cnt = 0
        self.output = open('timeWithoutTraffic.txt','w')
        self.timeCnt = 0
        self.tStart = 0
        self.tEnd = 0
        self.port_desc = []
        self.monitor_thread = hub.spawn(self._monitor)


        #self.topology_api_app = self

    #switch features event handler
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        sw_id = datapath.id


    #switch state change event handler
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_dst= '01:80:c2:00:00:0e',eth_type=0x88cc)
        actions = []
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.info('register datapath: %016d', datapath.id)
                self.datapaths[datapath.id] = datapath
                self.datapaths_id.append(datapath.id)
                print self.datapaths_id
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
                self.add_flow(datapath,65535,match,actions)
                #self.add_flow(datapath,65535,parser.OFPMatch(),actions)


        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('unregister datapath: %016d', datapath.id)
                del self.datapaths[datapath.id]
                self.traffic_cnt = 0

    def _monitor(self):
        while True:
            self.tStart = time.time()
            self._request_stats()

            #print end-start


            self.timeCnt +=1
            hub.sleep(1)
            self.lldp_pkt_cnt =0
            self.packet_out_cnt = 0

    def _request_stats(self):
        if len(self.datapaths) >0:
                for i in range(0,len(self.datapaths),1):
                    print "dpid: "+str(self.datapaths[self.datapaths_id[i]].id)
                    #port_desc = str(self.datapaths[self.datapaths_id[i]].ports[])
                    #print self.datapaths[self.datapaths_id[i]].ports.values()[0][0]

                    for j in range(0,len(self.datapaths[self.datapaths_id[i]].ports)-1,1):
                        #print "dpid:"+str(self.datapaths[i].id)+" p:"+str(self.datapaths[i].ports[j][0])
                        port_no = self.datapaths[self.datapaths_id[i]].ports.values()[j][0]
                        port_haddr = self.datapaths[self.datapaths_id[i]].ports.values()[j][1]
                        print port_no,port_haddr

                        actions = [self.datapaths[self.datapaths_id[i]].ofproto_parser.OFPActionOutput(port_no)]
                        self.send_packetOut(self.datapaths[self.datapaths_id[i]],int(port_no),
                                            str(port_haddr),actions)
                        self.packet_out_cnt +=1


                #self.send_barrier_request(self.datapaths[self.datapaths_id[i]])

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

    def send_packetOut(self,dp,port_no, dl_addr,actions):
        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            buffer_id=dp.ofproto.OFP_NO_BUFFER,
            actions=actions,
            data=LLDPPacket.lldp_packet(dp.id,port_no,dl_addr,120))
        dp.send_msg(out)

    def send_barrier_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPBarrierRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        self.logger.info('OFPBarrierReply received')
        self.tEnd = time.time()
        self.logger.info(self.tEnd-self.tStart)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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
            '''
            self.lldp_pkt_cnt +=1
            if self.lldp_pkt_cnt == 8:
                self.tEnd = time.time()
                self.output.write(str(self.timeCnt)+','+str(self.tEnd-self.tStart)+'\n')
            #print self.lldp_pkt_cnt
            '''
            return
        dst = eth.dst
        src = eth.src
        '''
        if src == '00:00:00:00:00:01' and dst == '00:00:00:00:00:02':
            #print self.traffic_cnt


            self.traffic_cnt+=1
            if self.traffic_cnt == 1:
                self.tStart = time.time()
            elif self.traffic_cnt == 2:
                self.tEnd = time.time()
                print self.tEnd-self.tStart
                self.traffic_cnt = 0

            return
        '''

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        actions1 = [None]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
		self.all_flow(datapath, 1, match, actions1)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
