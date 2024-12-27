# Copyright (c) 2024 Denis Berezhnoy

from enum import Enum

#
# PCAP file type
#
class PcapType(Enum):
    PCAP     = 0
    PCAPNG   = 1

#
# Physical link type
#
class LinkType(Enum):
    INVALID  = -1 # Invalid
    NULL     = 0  # BSD loopback encapsulation.
    ETHERNET = 1  # IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up)
#
# Protocol encapsulated in the payload of the eth frame
#
class EthType(Enum):
    INVALID  = -1 # Invalid
    IPv4     = 0  # IPv4
    IPv6     = 1  # IPv6

#
# Transport layer protocols
#
class TransportProtocolType(Enum):
    INVALID  = -1 # Invalid
    TCP      = 0  # TCP
    UDP      = 1  # UDP
