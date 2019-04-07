import argparse
import sys
import socket
import random
import struct

from scapy.all import * 



def get_if():
    ifs = get_if_list()
    iface = None 
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    
    if len(sys.argv)<3:
        print("pass 1 argument: <destination>")
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()


    pcap = rdpcap("../dns0313_2_onlyDNS.pcapng")

    q_pkt = []
    for pkt in pcap:
        if pkt.qr == 0: # the packet is query
            q_pkt.append(pkt)

    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=addr) / UDP(dport=53, sport=random.randint(49152,65535)) / q_pkt[DNS]
    sendp(pkt, iface = iface, verbose=False)

if __name__ == '__main__':
    main()
    
