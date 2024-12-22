import sys
import struct
from enum import Enum

VER_MAJOR = 0
VER_MINOR = 1

class LinkType(Enum):
    INVALID  = -1 # Invalid
    NULL     = 0  # BSD loopback encapsulation.
    ETHERNET = 1  # IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up)

class EthType(Enum):
    INVALID  = -1 # Invalid
    IPv4     = 0  # IPv4
    IPv6     = 1  # IPv6

usage_str = f"Usage: {sys.argv[0]} pcap_filename"

#
# Main
#
def main():

    if len(sys.argv) == 1:
        print(usage_str)
        sys.exit(1)

    pcap_filename = sys.argv[1]
    print(f"Pcap player (v{VER_MAJOR}.{VER_MINOR})")
    print(f"Open pcap file: {pcap_filename}")
    with open(pcap_filename, "rb") as pcap_file:

        link_type = parse_and_validate_header(pcap_file)
        if link_type == LinkType.INVALID:
            sys.exit(1)

        print("Parsing and sending records")
        while parse_and_send_payload(pcap_file, link_type):
            pass

    print("Done!")
    sys.exit(0)

#
#
#
def parse_and_validate_header(pcap_file):

    # File header format:
    # Magic Number (32 bits)
    # Major Version (16 bits)
    # Minor Version (16 bits)
    # Reserved1 (32 bits)
    # Reserved2 (32 bits)
    # SnapLen (32 bits)
    # LinkType (32 bits)
    header_fmt = 'IHHIIII'
    header_size = struct.calcsize(header_fmt)
    header_unpack = struct.Struct(header_fmt).unpack_from 
    header_bytes = pcap_file.read(header_size)
    magic_num, major_ver, minor_ver, reserved1, reserved2, snap_len, link_type = header_unpack(header_bytes)

    link_type &= 0x0FFFFFFF 

    print(f"Header: Magic Number {magic_num:#X} Major Version {major_ver} Minor Version {minor_ver} Link Type {link_type}")

    if magic_num != 0xA1B2C3D4 and magic_num != 0xA1B23C4D:
        print(f"ERROR: Unexpected magic number value {magic_num:#x}")
        return LinkType.INVALID

    # Only LINKTYPE_ETHERNET is supported now
    if link_type != LinkType.ETHERNET.value:
       print(f"ERROR: Unsupported link type {link_type}")
       return LinkType.INVALID

    print(f"Link Type {LinkType(link_type).name}")
    return LinkType(link_type)


frame_num_g = 0

#
#
#
def parse_and_send_payload(pcap_file, link_type):

    data_len = parse_packet_record(pcap_file)
    if data_len == 0:
        return False

    global frame_num_g
    frame_num_g += 1
    print(f"Frame {frame_num_g}")

    if link_type == LinkType.ETHERNET:
       return parse_eth2_frame(pcap_file, data_len)

    return False
#
#
#
def parse_packet_record(pcap_file):

    record_fmt = 'IIII'
    record_size = struct.calcsize(record_fmt)
    record_unpack = struct.Struct(record_fmt).unpack_from 
    record_bytes = pcap_file.read(record_size)
    if not record_bytes:
         return 0

    timestamp_1, timestamp_2, captured_len, origin_len = record_unpack(record_bytes)
    if (captured_len != origin_len):
        print("WARNING: len error") 

    return captured_len
#
#
#
def parse_eth2_frame(pcap_file, eth_frame_len):

    data = pcap_file.read(eth_frame_len)
    eth_type =  EthType.INVALID
    if data[12] == 0x08 and data[13] == 0x00:
        eth_type = EthType.IPv4
        print (f"{eth_type.name}")
        return True
    else:
        print (f"Unsupported eth type {data[12]:x}{data[13]:x}")
        return False

if __name__ == "__main__":
    main()