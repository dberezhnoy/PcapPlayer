import socket
import sys
import struct
import argparse
from enum import Enum

VER_MAJOR = 0
VER_MINOR = 2

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

#
#
#
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
#
#
#
class AppCtx:
    def __init__(self):
        # Input args
        self.pcap_filename = None
        self.in_frame_nums = None
        # App context
        self.frame_list    = None
        self.cur_frame     = None

#
#  parse_input_frame_nums
#
def parse_input_frame_nums(frame_nums):
    list_of_nums = [int(num.strip()) for num in frame_nums.split(",")]
    return list_of_nums
#
# Main
#
def main():

    print(f"Pcap player (v{VER_MAJOR}.{VER_MINOR})")

    # Parse input arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', type=str, required=True, help='pcap filename')
    parser.add_argument('--frames', type=str, required=True, help='Comma separated list of frame nums: 1,2,3')
    parser.add_argument('--replay_to', type=str, required=False, help='Remote host and port (host:port) to send frames')
    args = parser.parse_args()
    if args.pcap is None:
        parser.error("pcap filename cannot be empty")
    if args.frames is None:
        parser.error("frames list cannot be empty")

    ctx = AppCtx()
    ctx.pcap_filename = args.pcap
    ctx.in_frame_nums = parse_input_frame_nums(args.frames)
    ctx.frame_list = []

    run_app(ctx)

    print("\nDone!")
    sys.exit(0)

#
# run_app
#
def run_app(ctx):

    print(f"Open pcap file: {ctx.pcap_filename}")
    with open(ctx.pcap_filename, "rb") as pcap_file:

        link_type = parse_and_validate_header(pcap_file)
        if link_type == LinkType.INVALID:
            sys.exit(1)

        print(f"\nReading frames: {ctx.in_frame_nums}")
        while read_parse_frames(pcap_file, link_type, ctx):
            pass
        print("Done!")

        print(f"\nProcessing frames:")
        process_frames(ctx)

#
# parse_and_validate_header
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

    return captured_len
#
#
#
def parse_eth2_frame(pcap_file, eth_frame_len, ctx):

    data = pcap_file.read(eth_frame_len)
    eth_type =  EthType.INVALID
    if data[12] == 0x08 and data[13] == 0x00:
        eth_type = EthType.IPv4

    if frame_num_g not in ctx.in_frame_nums:
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
    for frame_num in ctx.in_frame_nums:
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