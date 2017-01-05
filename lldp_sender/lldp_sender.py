#!/usr/bin/python
'''
Created on Jun 8, 2013

@author: Alexandru Nicolae
'''
from LLDP_TLV import *

from scapy.all import *
from sys import exit
import string
import random
import re
from IPy import IP #this program is used to validate IPv4 and IPv6 addresses
import time
import os

br_name = []
port_name = []
br_dpid = []
port_macToDpid = {}
port_macToPortNo = {}
port_macToName = {}
port_mac = ""
dpid = ""
port_no = ""
mac_list = []

for br_info in os.popen('sudo ovs-vsctl show'):
    if 'Bridge' in br_info:
        br_name.append(br_info.split('"')[1])
#print br_name
if len(br_name) == 0:
    print "no ovs open"
    exit(0)
for name in br_name:
    for br_opf_info in os.popen('sudo ovs-ofctl show '+str(name)):
        if 'dpid' in br_opf_info:
            dpid = br_opf_info.split('dpid:')[1].strip('\n')
            br_dpid.append(br_opf_info.split('dpid:')[1].strip('\n'))
        if 'addr' in br_opf_info:
            port_mac = br_opf_info.split('addr:')[1].strip('\n')
            mac_list.append(port_mac)
            port_macToDpid[port_mac] = dpid
            port_no = br_opf_info.split('(')[0].strip(' ')
            port_macToPortNo[port_mac] = port_no
            port_name = br_opf_info.split('(')[1].split(')')[0]
            port_macToName[port_mac] = port_name


#This function's scope is to create a LLDP frame based on CLI commands
def create_packet(mac):

    frame = Ether()
    frame.dst = '01:80:c2:00:00:0e' #LLDP multicast address
    frame.src =  str(mac) #the frame's source is equal with the Port ID value
    frame.type = 0x88cc # LLDP ethertype

    packet = frame
    chid = None
    portid = None
    ttl = None
    interface = None
    port_desc = sys_name = sys_desc = sys_cap = mgm_add = port_vid = pp_vid = vlan_name = prot_id \
    = vid_digest = mgm_vid = link_agg1 = link_agg3 = mac_phy = power = max_frame = None

    med_cap = med_policy = None

    result = [] # two elements list: [packet,out_interface]
    mandatories = [] # mandatory TLVs list: chid, portid,ttl [endpdu]
    optionals= [] # optionals TLVs
    med_mandatories = []
    med_optionals = []
    tlvs = []

    #set chassis_ID
    chid = Chassis_ID()
    chid.subtype = 0x07
    chid.addrType = 0x00
    chid.locallyAssigned = "dpid:"+port_macToDpid[mac] #switch dpid
    chid.length = len("dpid:"+port_macToDpid[mac]) + 1
    mandatories.insert(0,chid)

    #set Port_ID
    portid = Port_ID()
    portid.subtype = 0x02
    portid.addrType = 0x00
    portid.portComponent = port_macToPortNo[mac]
    portid.length = len(port_macToPortNo[mac]) + 1
    mandatories.insert(1,portid)

    #set ttl
    ttl = TTL()
    ttl.seconds = 120
    mandatories.append(ttl)

    med_cap = MEDCapabilitiesTLV()
    med_mandatories.insert(0, med_cap)

    tlvs = mandatories + optionals + med_mandatories + med_optionals
    end_pdu = EndOfPDU()
    tlvs.append(end_pdu)

    for cnt in range (0,len(tlvs)):
        packet /= tlvs[cnt]

    result.insert(0,packet)

    if (interface == None):
        interface=port_macToName[mac]

    result.append(interface)

    return result

if __name__ == '__main__':

    packet = None
    interface = None
    for mac in mac_list:
        try:
            result = create_packet(mac) #create packet based on CLI informations
            #if the interface is not specified, eth0 is considered default

            packet = result[0]
            interface = result[1]


            #packet.show() #uncomment this for debugging a packet

            #ans,unans = srp(packet,verbose=1,iface=interface) #send and receive answers
            sendp(packet,verbose=1,iface=interface) #only send
            print "Output interface: "+interface
        except :
            continue
