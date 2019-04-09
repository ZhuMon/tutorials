#!/usr/bin/env python
import sys
import struct
import os

"""
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw, DNS
from scapy.all import rdpcap
"""
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):
    if UDP in pkt and pkt[UDP].dport == 53:
        print "got a packet"
        sys.stdout.flush()
        for rp in r_pkt:
            if pkt[DNS].id == rp[DNS].id and pkt.qd == rp.qd:
                pass_pkt(pkt, rp)
                break


    #    hexdump(pkt)

def pass_pkt(q,r):
    p = Ether(src = q[Ether].dst, dst=q[Ether].src)
    p = p / IP(dst=q[IP].src) / UDP(dport=q[UDP].sport, sport=53) / r.getlayer(DNS)
    sendp(p, iface = iface, verbose=False)

def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    global iface
    iface = ifaces[0]
    print("iface: ", iface)

    if len(sys.argv) < 2:
        print("pass 1 argument: <file.pcap>")
        exit(1)

    global pcaps # store the packets from .pcap
    global r_pkt # store the packets is received
    
    pcaps = rdpcap(sys.argv[1])
    r_pkt = []

    for pkt in pcaps:
        if pkt.qr == 1: # the packet is response
            r_pkt.append(pkt)


    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
