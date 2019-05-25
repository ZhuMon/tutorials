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
                  inout standard_metadata_t standard_metadata//,
                  //in    psa_ingress_input_metadata_t  istd,
                  //inout psa_ingress_output_metadata_t ostd
                  ) {

    register<bit<32>>(NUM) reg_ingress;
    //meter(10, MeterType.packets) my_meter;
    meter(MAX_NUM, MeterType.bytes) ingress_meter_stats;
    MeterColor ingress_meter_output = MeterColor_GREEN;

    action drop() {
        mark_to_drop();
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

    /*action m_action(bit<32> meter_index){
        my_meter.execute_meter((bit<32>) meter_index, meta.meter_tag);
    }

    action set_tos(bit<8> tos){
        hdr.ipv4.diffserv = tos;
    }

    table phy_forward {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table m_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            m_action;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table m_filter {
        key = {
            meta.meter_tag: exact;
        }
        actiosn = {
            set_tos;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }*/
    
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
        ingress_meter_stats.execute_meter<MeterColor>((bit<32>) standard_metadata.ingress_port, ingress_meter_output);

        if (hdr.ipv4.isValid()) {
            if (hdr.dns.isValid()){
                if (hdr.dns.qr == 0){ //dns is request
                    reg_ingress.write((bit<32>)hdr.dns.id, ((bit<32>)hdr.dns.id));
                    ipv4_lpm.apply();
                } else { //dns is response
                    
	            reg_ingress.read(tmp, (bit<32>)hdr.dns.id);
                    if (tmp == ((bit<32>)hdr.dns.id)){
                        ipv4_lpm.apply();
                        //drop();
                    } else if(ingress_meter_output == MeterColor_YELLOW) {
                        //phy_forward.apply();
                        //m_table.apply();
                        //m_filter.apply();
                        //drop();
                        //ipv4_lpm.apply();
                        mark_to_drop();
                    } else{
			ipv4_lpm.apply();
		    }
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
