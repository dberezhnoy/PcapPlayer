VER_MAJOR = 1
VER_MINOR = 0

#
# Ethernet frame with IPv4/TCP protocols
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
# Application context
#
class Ctx:
    def __init__(self):
        # Input args
        self.pcap_filename  = None
        self.in_frame_nums  = None
        self.replay_to_url  = None
        self.delay_ms       = 0
        # App context
        self.frame_list    = None
        self.cur_frame     = None
        self.server_sock   = None

URL_SCHEME_PLAIN_TCP = "plain-tcp"
URL_SCHEME_TLS_TCP   = "tls-tcp"
