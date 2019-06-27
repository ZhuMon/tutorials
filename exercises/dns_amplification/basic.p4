/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
//#include <psa.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86dd;
const bit<8>  TYPE_UDP  = 0x11;
const bit<32> NUM = 65536;
const bit<32> MAX_NUM = 8;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
//typedef bit<64> ip6Addr_t;
typedef bit<16> mcast_group_t;
typedef bit<2> MeterColor;
const MeterColor MeterColor_GREEN = 2w1;
const MeterColor MeterColor_YELLOW = 2w2;

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
    bit<16> qname;
    bit<16> qtype;
    bit<16> qclass;
}

struct metadata {
    //bit<32>   meter_tag;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    dns_t        dns;
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
        transition accept;
    }

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
                  inout standard_metadata_t standard_metadata
                  ) {

    register<bit<32>>(NUM) reg_ingress;
    register<bit<32>>(1) r_reg; // record # of DNS response 
    register<bit<32>>(1) f_reg; // flag to determine if do project
    //meter(10, MeterType.packets) my_meter;
    meter(MAX_NUM, MeterType.bytes) ingress_meter_stats;
    MeterColor ingress_meter_output = MeterColor_GREEN;

    action drop() {
        mark_to_drop(standard_metadata);
    }

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
        bit<32> index;
	bit<32> tmp;
        bit<32> flag;
        ingress_meter_stats.execute_meter<MeterColor>((bit<32>) standard_metadata.ingress_port, ingress_meter_output);

        if (hdr.ipv4.isValid()) {
            if (hdr.dns.isValid()){
                if(hdr.dns.qr == 1){
                    r_reg.read(tmp, 0);
                    r_reg.write(0, tmp+1);
                }

                f_reg.read(flag, 0);
                if (flag > 0){
                    if (hdr.dns.qr == 0){ //dns is request
                        index = (hdr.ipv4.srcAddr << 24) >> 24;
                        index = index % 64;
                        index = index << 10;
                        index = index + ((bit<32>)hdr.dns.id % 1024);
                        reg_ingress.read(tmp, index);
                        reg_ingress.write(index, tmp+10);
                        /*reg_ingress.write(0, index);*/
                        ipv4_lpm.apply();
                    } else { //dns is response
                        index = (hdr.ipv4.dstAddr << 24) >> 24;
                        index = index % 64;
                        index = index << 10;
                        index = index + ((bit<32>)hdr.dns.id % 1024);
                        
                        reg_ingress.read(tmp, index);
                        if (tmp > 10){
                            reg_ingress.write(index, tmp - 10);
                            ipv4_lpm.apply();
                        } else if (tmp > 0){
                            reg_ingress.write(index, 0);
                            ipv4_lpm.apply();
                        } else if(ingress_meter_output == MeterColor_YELLOW) {
                            drop();
                        } else{
                            ipv4_lpm.apply();
                            
                        }
                    }
                } else {
                    ipv4_lpm.apply();
                }
            } else {
                //ipv4_lpm.apply();
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
        //packet.emit(hdr.dns_qd);
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
