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

    magic_number, major_version, minor_version, reserved1, reserved2, snap_len, link_type = header_unpack(header_bytes)
    header = Header(magic_number, major_version, minor_version, reserved1, reserved2, snap_len, link_type)
    #header.magic_number = magic_number
    #header.major_version = major_version
    #header.minor_version = minor_version
    #header.reserved1 =  reserved1
    #header.reserved2 =  reserved2
    #header.snap_len = snap_len
    #header.link_type = link_type

    return header 
   
   