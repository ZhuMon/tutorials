/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
//#include <psa.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86dd;
const bit<8>  TYPE_UDP  = 0x11;
const bit<32> NUM = 65536;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
//typedef bit<64> ip6Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

/*header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payloadLen;
    bit<8>    nextHeader;
    bit<8>    hlim;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}*/

header udp_t {
    bit<16>   sport;
    bit<16>   dport;
    bit<16>   len;
    bit<16>   chksum;
}

header dns_t {
    bit<16>   id;
    bit<1>    qr;
    bit<4>    opcode;
    bit<1>    aa;
    bit<1>    tc;
    bit<1>    rd;
    bit<1>    ra;
    bit<1>    z;
    bit<1>    ad;
    bit<1>    cd;
    bit<4>    rcode;
    bit<16>   qdcount;
    bit<16>   ancount;
    bit<16>   nscount;
    bit<16>   arcount;
    //dns_qd  qd;   // remember to change
    //dns_an  an;
    //bit<32>  ns;
    //bit<32>  ar;
}
header dns_qd_t {
    bit<16> qname;
    bit<16> qtype;
    bit<16> qclass;
}

/*header dns_as_t {
    bit<16> rrname;
    bit<16> rtype;
    bit<16> rclass;
    bit<32> rttl;
    bit<16> rdlen;
}

header dns_as_rdata_t {
    varbit<524288> rdata;
}*/

header dns_as_t {
    bit<16> rrname;
    bit<16> rtype;
    bit<16> rclass;
    bit<32> rttl;
    bit<16> rdlen;
    varbit<524288> rdata;
}



struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    dns_t        dns;
    dns_qd_t     dns_qd;
    dns_as_t     dns_an;
    //dns_as_rdata_t  dns_an_rdata;
    //dns_as_t[65536]        dns_ns;
    //dns_as_rdata_t  dns_ns_rdata;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata
               ) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            //TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_udp {
        packet.extract(hdr.udp);
        packet.extract(hdr.dns);
        packet.extract(hdr.dns_qd);
        //tmp = hdr.dns.ancount;
        transition select(hdr.dns.ancount) {
            0: accept;
            _: parse_dns_an;
        }
    }

    //bit<16> tmp;
    state parse_dns_an {
    //for i in range(0, hdr.dns.ancount)
        packet.extract(hdr.dns_an, (bit<32>)(hdr.dns_an.rdlen*8+96));
        transition accept;
        //tmp = tmp - 1;
        /*transition select(hdr.dns.ancount-hdr.dns_an.nextindex){
            0: accept;
            _: parse_dns_an;
        }*/
    }

    /*state parse_dns_an_rdata {
        packet.extract(hdr.dns_an_rdata, (bit<32>)((bit<16>)hdr.dns_an.rdlen*32));
        transition select(hdr.dns.nscount) {
            0: accept;
            _: parse_dns_ns;
        }
    }

    state parse_dns_ns {
        packet.extract(hdr.dns_ns);
        transition select(hdr.dns_ns.rdlen){
            0: accept;
            _: parse_dns_ns_rdata;
        }

    }

    state parse_dns_ns_rdata {
        packet.extract(hdr.dns_ns.dns_as_rdata, (bit<32>)((bit<16>)hdr.dns_ns.rdlen*32));
        transition accept;
    }*/
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata//,
                  //in    psa_ingress_input_metadata_t  istd,
                  //inout psa_ingress_output_metadata_t ostd
                  ) {

    register<bit<32>>(NUM) reg_ingress;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    /*action update_count (inout PacketByteCountState_t s,
			 in bit<16> ip_length_bytes)
    {
	s[PACKET_COUNT_RANGE] = s[PACKET_COUNT_RANGE] + 1;
	s[BYTE_COUNT_RANGE] = (s[BYTE_COUNT_RANGE] + (bit<BYTE_COUNT_WIDTH>) ip_length_bytes)
    }*/
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    
    apply {
	bit<32> tmp;
        if (hdr.ipv4.isValid()) {
            if (hdr.dns.isValid()){
                ipv4_lpm.apply();
                /*
                if (hdr.dns.qr == 0){ //dns is request
                    //reg_ingress.write((bit<32>)hdr.ethernet.srcAddr[47:16], ((bit<32>)hdr.dns.id)+hdr.ethernet.srcAddr[47:16]);
                    ipv4_lpm.apply();
                } else { //dns is response
                    
	            //reg_ingress.read(tmp, (bit<32>)hdr.ethernet.srcAddr[47:16]);
                    /*if (tmp == ((bit<32>)hdr.dns.id)+hdr.ethernet.dstAddr[47:16]){
                        ipv4_lpm.apply();
                    } else {
                        drop();
                    }
                    ipv4_lpm.apply();
                }*/
            } else {
                drop();
            }
        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata
                 ) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.dns);
        packet.emit(hdr.dns_qd);
        packet.emit(hdr.dns_an);
        //packet.emit(hdr.dns_an_rdata);
        //packet.emit(hdr.dns_ns);
        //packet.emit(hdr.dns_ns_rdata);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
