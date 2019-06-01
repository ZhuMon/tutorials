#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

def writeIPRules(p4info_helper, ingress_sw, dst_eth_addr, dst_ip, mask, port):
    table_entry = p4info_helper.buildTableEntry(
    table_name = "MyIngress.ipv4_lpm",
    match_fields = {
	"hdr.ipv4.dstAddr": (dst_ip, mask)
    },
    action_name = "MyIngress.ipv4_forward",
    action_params={
        "dstAddr":dst_eth_addr,
	"port":port
    })
    ingress_sw.WriteTableEntry(table_entry)

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def printRegister(p4info_helper, sw, register_name, index):
    for response in sw.ReadRegisters(p4info_helper.get_register_name(register_name), index):
        for entity in response.entities:
            register = entity.register_entry
            print "%s %s %d: %s" % (sw.name, register_name, index, register.data)

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')

        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')
        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"

        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s2"

        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s3"

        register_entry = p4info_helper.buildRegisterEntry(
            register_name = "reg_ingress",
            index = 0,
            data = "\000"
        )
        s1.WriteRegisterEntry(register_entry)
        print "Write device_id to register on s1"

	#############################################################################
	writeIPRules(p4info_helper, ingress_sw=s1, dst_eth_addr="00:00:00:00:01:01", dst_ip="10.0.1.1", mask=32, port=1)
	writeIPRules(p4info_helper, ingress_sw=s1, dst_eth_addr="00:00:00:03:03:00", dst_ip="10.0.3.3", mask=32, port=2)
	writeIPRules(p4info_helper, ingress_sw=s2, dst_eth_addr="00:00:00:00:02:02", dst_ip="10.0.2.2", mask=32, port=1)
	writeIPRules(p4info_helper, ingress_sw=s2, dst_eth_addr="00:00:00:02:03:00", dst_ip="10.0.3.3", mask=32, port=2)
	writeIPRules(p4info_helper, ingress_sw=s3, dst_eth_addr="00:00:00:00:03:03", dst_ip="10.0.3.3", mask=32, port=1)
	writeIPRules(p4info_helper, ingress_sw=s3, dst_eth_addr="00:00:00:01:03:00", dst_ip="10.0.1.1", mask=32, port=2)
	writeIPRules(p4info_helper, ingress_sw=s3, dst_eth_addr="00:00:00:02:03:00", dst_ip="10.0.2.2", mask=32, port=3)

	#############################################################################


    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    tmp = raw_input()
    while tmp != 'a':
        print '\n---Reading Registers----\n'
        printRegister(p4info_helper, s1, "Myingress.reg_ingress", 20122)
        printRegister(p4info_helper, s1, "Myingress.reg_ingress", 1868)
        printRegister(p4info_helper, s1, "Myingress.reg_ingress", 0)
        tmp = raw_input()

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
