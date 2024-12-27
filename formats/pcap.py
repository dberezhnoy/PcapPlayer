# Copyright (c) 2024 Denis Berezhnoy

import struct

PCAP_FILE_EXT_STR = "pcap"

class Header:
    def __init__(self):
        self.magic_number  = None # Magic Number (32 bits)
        self.major_version = None # Major Version (16 bits)
        self.minor_version = None # Minor Version (16 bits)
        self.reserved1     = None # Reserved1 (32 bits)
        self.reserved2     = None # Reserved2 (32 bits)
        self.snap_len      = None # SnapLen (32 bits)
        self.link_type     = None # LinkType (32 bits)

    def __init__(self, magic_number, major_version, minor_version, reserved1, reserved2, snap_len, link_type):
        self.magic_number  = magic_number 
        self.major_version = major_version 
        self.minor_version = minor_version 
        self.reserved1     = reserved1 
        self.reserved2     = reserved2 
        self.snap_len      = snap_len  
        self.link_type     = link_type 


def read_header(pcap_file):

    header_fmt = 'IHHIIII'
    header_size = struct.calcsize(header_fmt)
    header_unpack = struct.Struct(header_fmt).unpack_from 
    header_bytes = pcap_file.read(header_size)
    if len(header_bytes) < header_size:
        return None

    magic_number, major_version, minor_version, reserved1, reserved2, snap_len, link_type = header_unpack(header_bytes)
    header = Header(magic_number, major_version, minor_version, reserved1, reserved2, snap_len, link_type)

    return header 

class Record:
    def __init__(self):
        self.timestamp              = None # 32 bits
        self.timestamp2             = None # 32 bits
        self.captured_packet_length = None # 32 bits
        self.original_packet_length = None # 32 bits

    def __init__(self, timestamp, timestamp2, captured_packet_length, original_packet_length):
        self.timestamp              = timestamp
        self.timestamp2             = timestamp2
        self.captured_packet_length = captured_packet_length
        self.original_packet_length = original_packet_length
   
def read_record(pcap_file):
    record_fmt = 'IIII'
    record_size = struct.calcsize(record_fmt)
    record_unpack = struct.Struct(record_fmt).unpack_from
    record_bytes = pcap_file.read(record_size)
    if len(record_bytes) < record_size:
        return None

    timestamp, timestamp2, captured_length, origin_length = record_unpack(record_bytes)
    record = Record(timestamp, timestamp2, captured_length, origin_length)

    return record
