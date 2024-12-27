# PcapPlayer
PcapPlayer is a command-line tool that takes in a list of frame numbers from a pcap file and replays them to the server.
## Description
Hi! The main goal of this project is to learn Python. Besides just learning Python, I also want to create something that could be useful to me and, hopefully, to somebody else. During my days as a datapath software designer, I used to deal with a lot of Wireshark traffic captures. Sometimes, the only way to reproduce an issue was to send the same packets to a server that were captured when the problem was seen. To do that, I used to open pcap files with Wireshark and copy-paste frames payload to my script. It was time consuming and boring, so I decided to create a tool to automate that.

I am pretty much sure that there are other tools that allow to do the same thing but I want to have my own tool that I am comfortable to modify in any way I want. So, please, welcome PcapPlayer!

## Usage
PcapPlayer is written in Python. To run it, you need Python3.
~~~
python3 pcapreplay.py -h
Pcap player (v1.0)
usage: pcapreplay.py [-h] --pcap PCAP --frames FRAMES [--replay_to REPLAY_TO] [--delay DELAY]

optional arguments:
  -h, --help            show this help message and exit
  --pcap PCAP           pcap filename
  --frames FRAMES       Comma separated list of frame nums: 1,2,3
  --replay_to REPLAY_TO
                        Remote host URL (plain-tcp://host:port) to send frames
  --delay DELAY         Delay in ms between sending frames
~~~
As --frames argument, PcapPlayer takes in a list of comma separated frame numbers to be extracted from the pcap file and sent to the server.  The order of the frames matters. PcapPlayer sends frames to the server in the specified order.  Duplicated frame numbers are allowed. PcapPlayer duplicates frames when sending the server as specified in the list.
~~~
python3 pcapreplay.py --pcap test/test2.pcap --frames=11,9,3,1,4,11,10,10 --replay_to=plain-tcp://localhost:2020
Pcap player (v1.0)
Open pcap file: test/test2.pcap
Header: Magic Number 0XA1B2C3D4 Major Version 2 Minor Version 4 Link Type 1
Link Type ETHERNET

Reading frames: [11, 9, 3, 1, 4, 11, 10, 10]
Frame 1: Skipping frame with no payload.
Frame 3: Skipping frame with no payload.
Frame 9: Skipping frame with no payload.
Done!

Connecting to plain-tcp://localhost:2020
Connected!

Processing frames:
Frame: 11
IPv4: src addr = 65.208.228.223 dst addr = 145.254.160.237
TCP : src port = 80 dst port = 3372 paylod len = 1380
Sent 1380 bytes to ('127.0.0.1', 2020)
Frame: 4
IPv4: src addr = 145.254.160.237 dst addr = 65.208.228.223
TCP : src port = 3372 dst port = 80 paylod len = 479
Sent 479 bytes to ('127.0.0.1', 2020)
Frame: 11
IPv4: src addr = 65.208.228.223 dst addr = 145.254.160.237
TCP : src port = 80 dst port = 3372 paylod len = 1380
Sent 1380 bytes to ('127.0.0.1', 2020)
Frame: 10
IPv4: src addr = 65.208.228.223 dst addr = 145.254.160.237
TCP : src port = 80 dst port = 3372 paylod len = 1380
Sent 1380 bytes to ('127.0.0.1', 2020)
Frame: 10
IPv4: src addr = 65.208.228.223 dst addr = 145.254.160.237
TCP : src port = 80 dst port = 3372 paylod len = 1380
Sent 1380 bytes to ('127.0.0.1', 2020)

Done! Number of processed frames: 5
~~~
PcapPlayer can also be used in dry run mode to read frames from pcap file without sending them to the server.
~~~
python3 pcapreplay.py --pcap test/test2.pcap --frames=11,9,3,1,4,11,10,10
Pcap player (v1.0)
Open pcap file: test/test2.pcap
Header: Magic Number 0XA1B2C3D4 Major Version 2 Minor Version 4 Link Type 1
Link Type ETHERNET

Reading frames: [11, 9, 3, 1, 4, 11, 10, 10]
Frame 1: Skipping frame with no payload.
Frame 3: Skipping frame with no payload.
Frame 9: Skipping frame with no payload.
Done!

Processing frames:
Frame: 11
IPv4: src addr = 65.208.228.223 dst addr = 145.254.160.237
TCP : src port = 80 dst port = 3372 paylod len = 1380
Frame: 4
IPv4: src addr = 145.254.160.237 dst addr = 65.208.228.223
TCP : src port = 3372 dst port = 80 paylod len = 479
Frame: 11
IPv4: src addr = 65.208.228.223 dst addr = 145.254.160.237
TCP : src port = 80 dst port = 3372 paylod len = 1380
Frame: 10
IPv4: src addr = 65.208.228.223 dst addr = 145.254.160.237
TCP : src port = 80 dst port = 3372 paylod len = 1380
Frame: 10
IPv4: src addr = 65.208.228.223 dst addr = 145.254.160.237
TCP : src port = 80 dst port = 3372 paylod len = 1380

Done! Number of processed frames: 5
~~~
## What is next
* Parsing pcapng format (PCAP Next Generation);
* Parsing IPv6 packets;
* Parsing UDP datagrams;
* Parsing various L2 frames;
* Making connections to a server via IPv6, SSL and UDP;
* Supporting anything fun that comes to my mind;
