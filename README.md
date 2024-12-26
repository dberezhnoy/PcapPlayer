# PcapPlayer
Hi! The main goal of this project is to learn Python. Besides just learning Python, I also want to create something that could be useful to me and, hopefully, to somebody else. During my days as a datapath software designer, I used to deal with a lot of Wireshark traffic captures. Sometimes, the only way to reproduce an issue was to send the same packets to a server that were captured when the problem was seen. To do that, I used to open pcap files with Wireshark and copy-paste frames payload to my script. It was time consuming and boring, so I decided to create a tool to automate that.

I am pretty much sure that there are other tools that allow to do the same thing but I want to have my own tool that I am comfortable to modify in any way I want.  So, please, welcome PcapPlayer!
PcapPlayer is a command-line tool that allows to specify a list of frame numbers that should be extracted from the pcap file and sent(replayed) to the server.
