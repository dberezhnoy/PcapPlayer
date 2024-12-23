import socket
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

class TransportProtocol(Enum):
    INVALID  = -1 # Invalid
    TCP      = 0  # TCP
    UDP      = 1  # UDP

class Frame:
    def __init__(self):
        self.frame_num    = 0
        self.captured_len = None
        self.origin_len   = None
        self.src_ip       = None
        self.src_port     = None
        self.dst_ip       = None
        self.dst_port     = None
        self.payload      = None
        self.payload_len  = 0

    def __eq__(self, other):
        return self.frame_num == other.frame_num

class AppCtx:
    def __init__(self):
        self.frame_nums = None
        self.frame_list = None
        self.cur_frame  = None

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

    ctx = AppCtx()
    ctx.frame_nums = [40, 38, 13, 15, 6]
    ctx.frame_list= []

    with open(pcap_filename, "rb") as pcap_file:

        link_type = parse_and_validate_header(pcap_file)
        if link_type == LinkType.INVALID:
            sys.exit(1)

        print(f"\nReading frames: {ctx.frame_nums}")
        while read_parse_frames(pcap_file, link_type, ctx):
            pass
        print("Done!")

        print(f"\nProcessing frames:")
        process_frames(ctx)

    print("\nDone!")
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
def read_parse_frames(pcap_file, link_type, ctx):

    data_len = parse_packet_record(pcap_file, ctx)
    if data_len == 0:
        return False

    if link_type == LinkType.ETHERNET:
       return parse_eth2_frame(pcap_file, data_len, ctx)

    return False
#
#
#
def parse_packet_record(pcap_file, ctx):

    record_fmt = 'IIII'
    record_size = struct.calcsize(record_fmt)
    record_unpack = struct.Struct(record_fmt).unpack_from 
    record_bytes = pcap_file.read(record_size)
    if not record_bytes:
         return 0

    global frame_num_g
    frame_num_g += 1

    ctx.cur_frame = Frame()

    timestamp_1, timestamp_2, captured_len, origin_len = record_unpack(record_bytes)
    ctx.cur_frame = Frame()
    ctx.cur_frame.frame_num    = frame_num_g
    ctx.cur_frame.captured_len = captured_len
    ctx.cur_frame.origin_len   = origin_len

    #if (captured_len < origin_len):
    #    ctx.cur_frame.frame_info_list.append(f"WARNING: Captured len {captured_len} is less than origin len {origin_len}")

    return captured_len
#
#
#
def parse_eth2_frame(pcap_file, eth_frame_len, ctx):

    data = pcap_file.read(eth_frame_len)
    eth_type =  EthType.INVALID
    if data[12] == 0x08 and data[13] == 0x00:
        eth_type = EthType.IPv4

    if frame_num_g not in ctx.frame_nums:
        return True
 
    match eth_type:
        case EthType.IPv4:
            return parse_ipv4_header(data[14:], ctx)
        case _:
            print (f"Frame {frame_num_g}: Skipped unsupported eth type {data[12]:#x}{data[13]:#x}.")
            return True

#      
#
#
def parse_ipv4_header(data, ctx):

    header_len = (data[0] & 0x0F) * 4
    ctx.cur_frame.src_ip = socket.inet_ntoa(data[12:16])
    ctx.cur_frame.dst_ip = socket.inet_ntoa(data[16:20])
    #ctx.cur_frame.frame_info_list.append (f"IPv4: src addr = {src_ip_addr} dst addr = {dst_ip_addr}")
    #ctx.cur_frame.src_ip = src_ip_addr
    #ctx.cur_frame.dst_ip = dst_ip_addr

    transport_protocol = TransportProtocol.INVALID
    if data[9] == 0x6:
        transport_protocol = TransportProtocol.TCP

    match transport_protocol:
        case TransportProtocol.TCP:
            parse_tcp_header(data[header_len:], ctx)
            return True
        case _:
            print(f"Frame {frame_num_g}: Skipping frame with unsupported transport protocol {data[9]:#x}.")
            return True
#
#
#
def parse_tcp_header(data, ctx):

    ctx.cur_frame.src_port = int.from_bytes(data[0:2], "big")
    ctx.cur_frame.dst_port = int.from_bytes(data[2:4], "big")  
    header_len = ((data[12] & 0xF0) >> 4) * 4
    ctx.cur_frame.payload_len = len(data) - header_len

    #ctx.cur_frame.src_ip = src_ip_addr
    #ctx.cur_frame.dst_ip = dst_ip_addr

    #ctx.cur_frame.frame_info_list.append(f"TCP : src port = {src_port} dst port = {dst_port} paylod len = {payload_len}")
    if ctx.cur_frame.payload_len == 0:
       print(f"Frame {frame_num_g}: Skipping frame with no payload.")
       return True

    return save_payload(data[header_len:], ctx)

def save_payload(data, ctx):
    ctx.cur_frame.payload = data
    ctx.frame_list.append(ctx.cur_frame)
    return True

def process_frames(ctx):
    for frame_num in ctx.frame_nums:
       #print(f"{frame_num}")
       frameToSearch = Frame()
       frameToSearch.frame_num = frame_num
       try:
           index = ctx.frame_list.index(frameToSearch)
           frame = ctx.frame_list[index]
           print(f"Frame: {frame.frame_num}")
           print(f"IPv4: src addr = {frame.src_ip} dst addr = {frame.dst_ip}")
           print(f"TCP : src port = {frame.src_port} dst port = {frame.dst_port} paylod len = {frame.payload_len}")
           if frame.captured_len < frame.origin_len:
               print(f"WARNING: Captured len {frame.captured_len} is less than origin len {frame.origin_len}")

           send_frame(frame, ctx)

       except:
           pass

    return True

def send_frame(frame, ctx):
    print("Sending frame...")
    return True
    
if __name__ == "__main__":
    main()