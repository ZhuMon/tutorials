import argparse
import sys
import socket
import random
import struct

from scapy.all import *
#from scapy.all import sniff, sendp, send, get_if_list, get_if_hwaddr
#from scapy.all import Packet, IPOption
#from scapy.all import Ether, IP, UDP, TCP, DNS
#from scapy.all import rdpcap


def get_if():
    ifs = get_if_list()
    iface = None 
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break;
    if not iface:
        print('Cannot find eth0 interface')
        exit(1)
    return iface

def handle_pkt(pkt):
    global num
    num = num + 1
    print num," got a response"
    # print pkt.show()
    if UDP in pkt and pkt[UDP].sport == 53:
	print num," ",pkt.getlayer(DNS).id
        sys.stdout.flush()

def main():
    
    #if len(sys.argv)<3:
    #    print('pass 2 argument: <destination> "<file.pcap>"')
    #    exit(1)

    # addr = socket.gethostbyname("10.0.3.3") # dns_server
    addr = "10.0.3.3"
    iface = get_if()
    print("iface: ", iface)

    pcap = rdpcap("dns0313_2_onlyDNS.pcapng")

    q_pkt = []
    for pkt in pcap:
        if pkt.qr == 0: # the packet is query
            q_pkt.append(pkt)

    N = raw_input()
    for i in range(0,int(N)):
        a = raw_input()
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        sport = random.randint(49152,65535)
        pkt = pkt /IP(dst=addr, src="10.0.1.1") / UDP(dport=53, sport=sport) / q_pkt[int(a)].getlayer(DNS)
        sendp(pkt, iface = iface, verbose=False)
        print "send a packet"
        sniff(stop_filter = lambda x: (x.haslayer(DNS) and x[DNS].id == pkt[DNS].id),
                iface = iface, 
                prn = lambda x: handle_pkt(x), 
                timeout = 5)
        
        #print "sniffing on %s" % iface
	
    sniff(iface = iface, prn = lambda x: handle_pkt(x))


if __name__ == '__main__':
    num = 0
    main()
    
