'''
Created on Jun 8, 2013

@author: Alexandru Nicolae
'''
#This module represents the definition of all LLDP TLVs 
#Informations about LLDP protocol can be found at: http://read.pudn.com/downloads139/sourcecode/others/600448/ieee8023_2005/802.1AB-2005.pdf

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, IP6Field



TLV_dictionary =  {0x00: "End of LLDPDU",
                   0x01: "Chassis Id",
                   0x02: "Port Id",
                   0x03: "Time to Live",
                   0x04: "Port Description",
                   0x05: "System Name",
                   0x06: "System Description",
                   0x07: "System Capabilities",
                   0x08: "Management Address",
                   0x7f: "Organiation Specific"
                   }

Chassis_ID_subtypes = {0x00: "Reserved",
                       0x01: "Chassis component",
                       0x02: "Interface alias",
                       0x03: "Port component",
                       0x04: "MAC address",
                       0x05: "Network address",
                       0x06: "Interface name",
                       0x07: "Locally assigned"}

Network_Address_Type = {0x01: "IPv4",
                        0x02: "IPv6"}

Port_ID_subtypes = {0x00: "Reserved",
                    0x01: "Interface alias",
                    0x02: "Port component",
                    0x03: "MAC address",
                    0x04: "Network address",
                    0x05: "Interface name",
                    0x06: "Agent circut ID",
                    0x07: "Locally assigned"}

System_Capabilities = {1: "Other",
             2: "Repeater",
             4: "MAC Bridge",
             8: "Wlan Acess Point",
             16: "Router",
             32: "Telephone",
             64: "Docsis cable device",
             128: "Station Only",
             256: "C-Vlan",
             512: "S-Vlan",
             1024: "Two Port Mac Relay"}

Management_Address_Subtype = {0x00: "Other",
                              0x01: "IPv4",
                              0x02: "IPv6"
                              }
Interface_Numbering_Subtype = {0x01: "Unknown",
                               0x02: "IfIndex",
                               0x03: "PortNumber"}

Organization_Specific_Type = {0x0080c2: "802.1 Subtype",
                              0x00120f: "802.3 Subtype"}

Dot1Subtypes = {0x01: "Port VLAN ID",
                0x02: "Port and Protocol VLAN ID",
                0x03: "VLAN Name",
                0x04: "Protocol Identity",
                0x05: "VID Usage Digest",
                0x06: "Management VID",
                0x07: "Link Aggregation",
                0x08ff: "Reserved"}

Dot3Subtypes = {0x01: "MAC/PHY Configuration/Status ",
                0x02: "Power Via Medium Dependent Interface (MDI)",
                0x03: "Link Aggregation",
                0x04: "Maximum Frame Size"}

""" bit2 bit1
    bit1 = Suported
    bit2 = Enabled
"""
PPVID_flags = {0x01: "Not suported and Not enabled",
               0x02: "Suported and Not enabled",
               0x04: "Not Suported and  Enabled",
               0x06: "Supported and Enabled"
               }
Link_Aggregation_Status = {0x00: "Not Capable for Aggregation - Not Enabled",
                           0x01: "Capable for Aggregation - Not Enabled",
                           0x02: "Not Capable for Aggregation - Enabled",
                           0x03: "Capable for Aggregation - Enabled"}

""" bit1 bit0
    bit0 = Support
    bit1 = Status
"""
AutoNegotiation_SS = {0x00: "Not Supported - Not Enabled",
                      0x01: "Supported - Not Enabled",
                      0x02: "Not Suported - Enabled",
                      0x03: "Supported - Enabled"}

# from: http://standards.ieee.org/findstds/interps/802.1AB.html
PMD_Capabilities = {1: "1000BASE-T full duplex mode",
                    2: "1000BASE-T half duplex mode",
                    4: "1000BASE-X, -LX, -SX, -CX full duplex mode ",
                    8: "1000BASE-X, -LX, -SX, -CX half duplex mode ",
                    16: "Asymmetric and Symmetric PAUSE for full-duplex inks ",
                    32: "Symmetric PAUSE for full-duplex links ",
                    64: "Asymmetric PAUSE for full-duplex links ",
                    128: "PAUSE for full-duplex links",
                    256: "100BASE-T2 full duplex mode",
                    512: "100BASE-T2 half duplex mode",
                    1024: "100BASE-TX full duplex mode",
                    2048: "100BASE-TX half duplex mode",
                    4096: "100BASE-T4",
                    8192: "100BASE-T full duplex mode",
                    16384: "10BASE-T half duplex mode "}

# Conform RFC 4836: http://www.ietf.org/rfc/rfc4836.txt
Operational_MAU_type = {0: "other or unknown",
                        1: "AUI",
                        2: "10BASE-5",
                        3: "FOIRL",
                        4: "10BASE-2",
                        5: "10BASE-T duplex mode unknown",
                        6: "10BASE-FP",
                        7: "10BASE-FB",
                        8: "10BASE-FL duplex mode unknown",
                        9: "10BROAD36",
                        10: "10BASE-T  half duplex mode",
                        11: "10BASE-T  full duplex mode",
                        12: "10BASE-FL half duplex mode",
                        13: "10BASE-FL full duplex mode",
                        14: "100BASE-T4",
                        15: "100BASE-TX half duplex mode",
                        16: "100BASE-TX full duplex mode",
                        17: "100BASE-FX half duplex mode",
                        18: "100BASE-FX full duplex mode",
                        19: "100BASE-T2 half duplex mode",
                        20: "100BASE-T2 full duplex mode",
                        21: "1000BASE-X half duplex mode",
                        22: "1000BASE-X full duplex mode",
                        23: "1000BASE-LX half duplex mode",
                        24: "1000BASE-LX full duplex mode",
                        25: "1000BASE-SX half duplex mode",
                        26: "1000BASE-SX full duplex mode",
                        27: "1000BASE-CX half duplex mode",
                        28: "1000BASE-CX full duplex mode",
                        29: "1000BASE-T half duplex mode",
                        30: "1000BASE-T full duplex mode",
                        31: "10GBASE-X",
                        32: "10GBASE-LX4",
                        33: "10GBASE-R",
                        34: "10GBASE-ER",
                        35: "10GBASE-LR",
                        36: "10GBASE-SR",
                        37: "10GBASE-W",
                        38: "10GBASE-EW",
                        39: "10GBASE-LW",
                        40: "10GBASE-SW",
                        41: "10GBASE-CX4",
                        42: "2BASE-TL",
                        43: "10PASS-TS",
                        44: "100BASE-BX10D",
                        45: "100BASE-BX10U",
                        46: "100BASE-LX10",
                        47: "1000BASE-BX10D",
                        48: "1000BASE-BX10U",
                        49: "1000BASE-LX10",
                        50: "1000BASE-PX10D",
                        51: "1000BASE-PX10U",
                        52: "1000BASE-PX20D",
                        53: "1000BASE-PX20U"}

MDI_Power_Support = {0: "Port class PD",
                     1: "Port class PSE",
                     2: "MDI power support: supported",
                     3: "MDI power support: supported - Port class PSE",
                     4: "MDI power state: enabled",
                     5: "MDI power state: enabled - Port class PSE",
                     6: "MDI power state: enabled - MDI power support: supported",
                     7: "MDI power state: enabled - MDI power support: supported - Port class PSE",
                     8: "Pair control: enabled",
                     9: "Pair control: enabled - Port class PSE",
                     10: "Pair control: enabled - MDI power support: supported ",
                     11: "Pair control: enabled - MDI power support: supported - PSE",
                     12: "Pair control: enabled - MDI power state: enabled",
                     13: "Pair control: enabled - MDI power state: enabled - PSE ",
                     14: "Pair control: enabled - MDI power state: enabled - MDI power support: supported",
                     15: "Pair control: enabled - MDI power state: enabled - MDI power support: supported - PSE" }

# Conform: http://tools.ietf.org/html/rfc3621 - page 7
MDI_Power_Pair = {1:"Signal pairs only are in use",
                  2: "The spare pairs only are in use"}

# Conform: http://tools.ietf.org/html/rfc3621 - page 9
MDI_Power_Class = {1:" C1",
                   2:" C2",
                   3:" C3",
                   4:" C4",
                   5:" C5"}

##################### MED subtypes ##########################

MED_Capabilities_Subtype = {1: "LLDP-MED Capabilities",
                            2: "Network Policy",
                            4: "Location Identification",
                            8: "Extended Power-via-MDI-PSE",
                            16: "Extended Power-via-MDI-PD",
                            32: "Inventory",
                            64: "Reserved"}

MED_Device_Type = {0: "Type not defined",
                   1: "Endpoint CLass 1",
                   2: "Endpoint Class 2",
                   3: "Endpoint Class 3",
                   4: "Network Connectivity",
                   5: "Reserved"}                            

MED_Application_Type = {0: "Reserved",
                        1: "Voice",
                        2: "Voice Signaling",
                        3: "Guest Voice",
                        4: "Guest Voice Signaling",
                        5: "Softphone Voice",
                        6: "Video Conferencing",
                        7: "Streaming Video",
                        8: "Video Signaling",
                        9: "Reserved"}

MED_Data_Format = {0: "Invalid",
                   1: "Coordinate-based LCI",
                   2: "Civic Adress LCI",
                   3: "ECS ELIN",
                   4: "Reserved"}

MED_MDI_Power_Type = {0: "PSE Device",
                      1: "PD Device",
                      2: "Reserved",
                      3: "Reserved"}

MED_MDI_Power_Source = {0: "Unknown",
                        1: "PSE",
                        2: "Local",
                        3: "PSE and Local"}

MED_MDI_Power_Priority = {0: "Unknown",
                          1: "Critical",
                          2: "High",
                          3: "Low",
                          4: "Reserved"}                                                                                 

"""All the logic behind layer manipulation is hold by the Packet class and will be inherited"""

""" Chassis ID TLV definition"""
class Chassis_ID(Packet):
    name = "Chassis ID"
    fields_desc = [BitEnumField("type", 0x01, 7, TLV_dictionary),
                   BitField("length", 7, 9),
                   ByteEnumField("subtype", 0x04, Chassis_ID_subtypes),
                   ConditionalField(StrLenField("reserved", "", length_from=lambda x: x.length - 1), lambda pkt: pkt.subtype == 0x00),
                   ConditionalField(StrLenField("chassisComponent", "chassis comp", length_from=lambda x: x.length - 1), lambda pkt: pkt.subtype == 0x01),
                   ConditionalField(StrLenField("interfaceAlias", "interface alias", length_from=lambda x: x.length - 1), lambda pkt: pkt.subtype == 0x02),
                   ConditionalField(StrLenField("portComponent", "port component", length_from=lambda x: x.length - 1), lambda pkt: pkt.subtype == 0x03),
                   ConditionalField(MACField("macaddr", "00:11:11:11:11:11"), lambda pkt: pkt.subtype == 0x04),
                   ConditionalField(ByteEnumField("addrType", 0x00, Network_Address_Type), lambda pkt: pkt.subtype == 0x05),
                   ConditionalField(IPField("ipaddr", "10.10.10.10"), lambda pkt: pkt.addrType == 0x01),
                   ConditionalField(IP6Field("ip6addr", "2002::1"), lambda pkt: pkt.addrType == 0x02),
                   ConditionalField(StrLenField("interfaceName", "lo0", length_from=lambda x: x.length - 1), lambda pkt: pkt.subtype == 0x06),
                   ConditionalField(StrLenField("locallyAssigned", "yes", length_from=lambda x: x.length - 1), lambda pkt: pkt.subtype == 0x07)]
                   
""" Port ID TLV definition"""
class Port_ID(Packet):
    name = "Port ID"
    fields_desc = [BitEnumField("type", 0x02, 7, TLV_dictionary),
                   BitField("length", 7, 9),
                   ByteEnumField("subtype",0x03, Port_ID_subtypes),
                   ConditionalField(StrLenField("reserved", "", length_from=lambda x: x.length - 1), lambda pkt: pkt.subtype == 0x00),
                   ConditionalField(StrLenField("interfaceAlias", "", length_from=lambda x: x.length - 1), lambda pkt: pkt.subtype == 0x01),
                   ConditionalField(StrLenField("portComponent", "", length_from=lambda x: x.length - 1), lambda pkt: pkt.subtype == 0x02),
                   ConditionalField(MACField("macaddr", "00:11:11:11:11:11"), lambda pkt: pkt.subtype == 0x03),
                   ConditionalField(ByteEnumField("addrType", 0x00, Network_Address_Type), lambda pkt: pkt.subtype == 0x04),
                   ConditionalField(IPField("ipaddr", "10.10.10.10"), lambda pkt: pkt.addrType == 0x01),
                   ConditionalField(IP6Field("ip6addr", "2002::1"), lambda pkt: pkt.addrType == 0x02),
                   ConditionalField(StrLenField("interfaceName", "lo0", length_from=lambda x: x.length - 1), lambda pkt: pkt.subtype == 0x05),
                   ConditionalField(StrLenField("agentCircutID", "id_agent", length_from=lambda x: x.length - 1), lambda pkt: pkt.subtype == 0x06),
                   ConditionalField(StrLenField("locallyAssigned", "yes", length_from=lambda x: x.length - 1), lambda pkt: pkt.subtype == 0x07)]

class TTL(Packet):
    name = "Time To Live"
    fields_desc = [BitEnumField("type", 0x03, 7, TLV_dictionary),
                   BitField("length", 0x02, 9),
                   ShortField("seconds",120)]
    

class EndOfPDU(Packet):
    name = "End of LLDPDU"
    fields_desc = [BitEnumField("type", 0x00, 7, TLV_dictionary),
                   BitField("length", 0x00, 9)]

class PortDescription(Packet):
    name = "Port Description"
    fields_desc = [BitEnumField("type", 0x04, 7, TLV_dictionary),
                   BitField("length", 0x07, 9),
                   StrLenField("portDescription", "eth 0/1", length_from=lambda x: x.length - 1)]

class SystemName(Packet):
    name = "System Name"
    fields_desc = [BitEnumField("type", 0x05, 7, TLV_dictionary),
                   BitField("length", 0x0b, 9),
                   StrLenField("systemName", "ASUS KVD-55", length_from=lambda x: x.length - 1)]
                             
class SystemDescription(Packet):
    name = "System Description"
    fields_desc = [BitEnumField("type", 0x06, 7, TLV_dictionary),
                   BitField("length", 0x0c, 9),
                   StrLenField("systemDescription", "Versiunea 10", length_from=lambda x: x.length - 1)]

                              

class SystemCapabilities(Packet):
    name = "System Capabilities"
    fields_desc = [BitEnumField("type", 0x07, 7, TLV_dictionary),
                   BitField("length", 0x04, 9),
                   #ByteEnumField("chid_subtype", 0x04, Chassis_ID_subtypes),
                   BitEnumField("systemCapabilities", 16, 16, System_Capabilities),
                   BitEnumField("enabledCapabilities", 16, 16, System_Capabilities)]

class ManagementAddress(Packet):
    name = "Management Address"
    fields_desc = [BitEnumField("type", 0x08, 7, TLV_dictionary),
                   BitField("length", 24, 9), # 17 + 1(IntNumsubtype) + 4(ifnumber) + 1(OidLen)+1(oid) 
                   ByteField("addrStrLen", 17), # 1(addrSubtype) + 16(ip6addr)
                   ByteEnumField("addrSubtype", 0x00, Management_Address_Subtype),
                   ConditionalField(IPField("ipaddr", "10.10.10.10"), lambda pkt: pkt.addrSubtype == 0x01),
                   ConditionalField(IP6Field("ip6addr", "2002::1"), lambda pkt: pkt.addrSubtype == 0x02),
                   ConditionalField(StrLenField("mgmAddress", "", length_from=lambda x: x.addrStrLen - 1), lambda pkt: pkt.addrSubtype not in [0x01, 0x02]),
                   ByteEnumField("intNumSubtype", 0x01, Interface_Numbering_Subtype),
                   IntField("ifnumber", 0),
                   BitField("oidLength", 0x00, 8),
                   StrLenField("oid",None, length_from=lambda x: x.oidLength)]

# Dot1 subtypes definition

class Port_Vlan_ID(Packet):
    name = "Port Vlan ID"
    fields_desc = [BitEnumField("type", 0x7f, 7, TLV_dictionary),
                   BitField("length", 0x06, 9),
                   BitEnumField("OUI", 0x0080c2, 24, Organization_Specific_Type),
                   ByteEnumField("subtype", 0x01, Dot1Subtypes),
                   BitField("PVID", 10, 16)]
    
class Port_And_Protocol_Vlan_ID(Packet):
    name = "Port and protocol Vlan ID"
    fields_desc = [BitEnumField("type", 0x7f, 7, TLV_dictionary),
                   BitField("length", 0x07, 9),
                   BitEnumField("OUI", 0x0080c2, 24, Organization_Specific_Type),
                   ByteEnumField("subtype", 0x02, Dot1Subtypes),
                   ByteEnumField("flags", 0x06, PPVID_flags),
                   BitField("PPVID", 10, 16)]
    
class Vlan_Name(Packet):
    name = "Vlan Name"
    fields_desc = [BitEnumField("type", 0x7f, 7, TLV_dictionary),
                   BitField("length", 16, 9), # 7 + 9
                   BitEnumField("OUI", 0x0080c2, 24, Organization_Specific_Type),
                   ByteEnumField("subtype", 0x03, Dot1Subtypes),
                   BitField("VID", 10, 16),
                   ByteField("nameLength", 9),
                   StrLenField("vlanName","nume_vlan",length_from=lambda x: x.nameLength)]
    

class Protocol_Identity(Packet):
    name = "Protocol Identity"
    fields_desc = [BitEnumField("type", 0x7f, 7, TLV_dictionary),
                   BitField("length", 15, 9),
                   BitEnumField("OUI", 0x0080c2, 24, Organization_Specific_Type),
                   ByteEnumField("subtype", 0x04, Dot1Subtypes),
                   ByteField("identityLength", 10),
                   StrLenField("identity","identitate",length_from=lambda x: x.identityLength)]

class VID_Usage_Digest(Packet): # DEPRECATED
    name = "VID Usage Digest"
    fields_desc = [BitEnumField("type", 0x7f, 7, TLV_dictionary),
                   BitField("length", 8, 9),
                   BitEnumField("OUI", 0x0080c2, 24, Organization_Specific_Type),
                   ByteEnumField("subtype", 0x05, Dot1Subtypes),
                   BitField("VID", 0, 32)]

class Management_VID(Packet): #DEPRECATED
    name = "Management Vlan ID"
    fields_desc = [BitEnumField("type", 0x7f, 7, TLV_dictionary),
                   BitField("length", 6, 9),
                   BitEnumField("OUI", 0x0080c2, 24, Organization_Specific_Type),
                   ByteEnumField("subtype", 0x06, Dot1Subtypes),
                   BitField("VID", 100, 16)]

class Link_Aggregation_Dot1(Packet): #DEPRECATED
     name = "Link Aggregation for Dot1q Subtype"
     fields_desc = [BitEnumField("type", 0x7f, 7, TLV_dictionary),
                   BitField("length", 9, 9),
                   BitEnumField("OUI", 0x0080c2, 24, Organization_Specific_Type),
                   ByteEnumField("subtype", 0x07, Dot1Subtypes),
                   ByteEnumField("status", 0x01, Link_Aggregation_Status),
                   BitField("PID", 1, 32)]

# Dot3 subtypes definition
     
class Mac_Phy_Configuration_Status(Packet):
    name = "MAC/PHY Configuration Status"
    fields_desc = [BitEnumField("type", 0x7f, 7, TLV_dictionary),
                   BitField("length", 9, 9),
                   BitEnumField("OUI", 0x00120f, 24, Organization_Specific_Type),
                   ByteEnumField("subtype", 0x01, Dot3Subtypes),
                   ByteEnumField("autoneg", 0x01, AutoNegotiation_SS),
                   BitEnumField("PMD", 128, 16, PMD_Capabilities),
                   BitEnumField("MAU_type", 13, 16, Operational_MAU_type)]

class Power_Via_MDI(Packet):
    name = "Power over Medium Dependent Interface (MDI)"
    fields_desc = [BitEnumField("type", 0x7f, 7, TLV_dictionary),
                   BitField("length", 7, 9),
                   BitEnumField("OUI", 0x00120f, 24, Organization_Specific_Type),
                   ByteEnumField("subtype", 0x02, Dot3Subtypes),  
                   ByteEnumField("powerSupport", 5, MDI_Power_Support),
                   ByteEnumField("powerPair", 1, MDI_Power_Pair),
                   ByteEnumField("powerClass", 3, MDI_Power_Class)]
    
class Link_Aggregation_Dot3(Packet):
     name = "Link Aggregation for Dot3 Subtype"
     fields_desc = [BitEnumField("type", 0x7f, 7, TLV_dictionary),
                   BitField("length", 9, 9),
                   BitEnumField("OUI", 0x00120f, 24, Organization_Specific_Type),
                   ByteEnumField("subtype", 0x03, Dot3Subtypes),
                   ByteEnumField("status", 0x02, Link_Aggregation_Status),
                   BitField("PID", 1, 32)]
    
class Maximum_Frame_Size(Packet):
    name = "Maximum frame size"
    fields_desc = [BitEnumField("type", 0x7f, 7, TLV_dictionary),
                   BitField("length", 6, 9),
                   BitEnumField("OUI", 0x00120f, 24, Organization_Specific_Type),
                   ByteEnumField("subtype", 0x04, Dot3Subtypes),
                   BitField("frameSize", 1518, 16)]  
                             
# LLDP MED TLVs

#All LLDP-MED LLDPDUs shall contain exactly one LLDP-MED Capabilities TLV, and this TLV shall
#always be the first LLDP-MED TLV contained in the LLDPDU.

class MEDCapabilitiesTLV(Packet):
    name = "LLDP-MED Capabilities"
    fields_desc = [BitEnumField("type", 0x7f, 7, TLV_dictionary),
                   BitField("length", 7, 9),
                   BitField("TIA_OUI", 0x00012BB, 24),
                   BitField("Subtype", 1, 8),
                   BitEnumField("Capabilities", 0x01, 16, MED_Capabilities_Subtype),
                   BitEnumField("Device_Type", 0x03, 8, MED_Device_Type)]

class MEDNetworkPolicyTLV(Packet):
    name = "Network Policy"
    fields_desc = [BitEnumField("type", 0x7f, 7, TLV_dictionary),
                   BitField("length", 8, 9),
                   BitField("TIA_OUI", 0x00012BB, 24),
                   BitField("Subtype", 2, 8),
                   ByteEnumField("Application_Type", 0x01, MED_Application_Type),
                   BitField("U", 0, 1),
                   BitField("T", 1, 1),
                   BitField("X", 0, 1),
                   BitField("VLAN_ID", 100, 12),
                   BitField("L2_Priority", 0, 3),
                   BitField("DSCP_Value", 0, 6)]

class MEDLocationIdentificationTLV(Packet):
    name = "Location Identification"
    fields_desc = [BitField("type", 0x7f,7),
                   BitField("length", 5, 9), # 256 + 5 octets is the maximum length
                   BitField("TIA_OUI", 0x00012BB, 24),
                   BitField("Subtype", 3, 8),
                   ByteEnumField("Data_Format", 0, MED_Data_Format),
                   BitField("Location_ID", 0, 128)] # from 0 to 256 octets

class MEDExtendedPowerviaMDITLV(Packet):
    name = "Extended Power-via-MDI"
    fields_desc = [BitField("type", 0x7f, 7),
                   BitField("length", 7, 9),
                   BitField("TIA_OUI", 0x00012BB, 24),
                   BitField("Subtype", 4, 8),
                   BitEnumField("Power_Type", 0x00, 2, MED_MDI_Power_Type),
                   BitEnumField("Power_Source", 0x00, 2, MED_MDI_Power_Source),
                   BitEnumField("Power_Priority", 0x00, 4, MED_MDI_Power_Priority),
                   BitField("Power_Value", 0, 16)] # from 0 to 1023 (102.3 Watts)

class MEDHardwareRevisionTLV(Packet):
    name = "Hardware Revision"
    fields_desc = [BitField("type", 0x7f, 7),
                   BitField("length", 24, 9),
                   BitField("TIA_OUI", 0x00012BB, 24),
                   BitField("Subtype", 5, 8),
                   StrLenField("Hardware_Revision","Default Hardware Rev",lambda x: x.length - 1)]

class MEDFirmwareRevisionTLV(Packet):
    name = "Firmware Revision"
    fields_desc = [BitField("type",0x7f,7),
                   BitField("length", 24, 9),
                   BitField("TIA_OUI", 0x00012BB, 24),
                   BitField("Subtype", 6, 8),
                   StrLenField("Firmware_Revision", "Default Firmware Rev", length_from=lambda x: x.length - 1)]

class MEDSoftwareRevisionTLV(Packet):
    name = "Software Revision"
    fields_desc = [BitField("type", 0x7f, 7),
                   BitField("length", 24, 9),
                   BitField("TIA_OUI", 0x00012BB, 24),
                   BitField("Subtype", 7, 8),
                   StrLenField("Software_Revision","Default Software Rev",length_from=lambda x: x.length - 1)]

class MEDSerialNumberTLV(Packet):
    name = "Serial Number"
    fields_desc = [BitField("type", 0x7f, 7),
                   BitField("length", 22, 9),
                   BitField("TIA_OUI", 0x00012BB, 24),
                   BitField("Subtype", 8, 8),
                   StrLenField("Serial_Number","Default Serial Num",length_from=lambda x: x.length - 1)]

class MEDManufacturerNameTLV(Packet):
    name = "Manufacturer Name"
    fields_desc = [BitField("type", 0x7f, 7),
                   BitField("length", 29, 9),
                   BitField("TIA_OUI", 0x00012BB, 24),
                   BitField("Subtype", 9, 8),
                   StrLenField("Manufacturer_Name", "Default Manufacturer Name",length_from=lambda x: x.length - 1)]

class MEDModelNameTLV(Packet):
    name = "Model Name"
    fields_desc = [BitField("type",0x7f,7),
                   BitField("length",4,9),
                   BitField("TIA_OUI",0x00012BB,24),
                   BitField("Subtype", 10, 8),
                   StrLenField("Model_Name","",length_from=lambda x: x.length - 1)]

class MEDAssetIDTLV(Packet):
    name = "Asset ID"
    fields_desc = [BitField("type",0x7f,7),
                   BitField("length",4,9),
                   BitField("TIA_OUI",0x00012BB,24),
                   BitField("Subtype", 11, 8),
                   StrLenField("Asset_ID","",length_from=lambda x: x.length - 1)]                   
