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
import runtime_CLI
import bmpy_utils as utils

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
    for response in sw.ReadRegisters(p4info_helper.get_registers_id(register_name), index, dry_run=False):
        for entity in response.entities:
            register = entity.register_entry
            print "%s %s %d: %s" % (sw.name, register_name, index, register.data.data.enum)

def printCounter(p4info_helper, sw, counter_name, index):
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print "%s %s %d: %d" % (
                sw.name, counter_name, index, counter.data.packet_count
            )

def read_register(runtimeAPI, name, index):
    reg = runtimeAPI.get_res("register", name, runtime_CLI.ResType.register_array)
    return runtimeAPI.client.bm_register_read(0, reg.name, index)

def write_register(runtimeAPI, name, index, value):
    register = runtimeAPI.get_res("register", name, runtime_CLI.ResType.register_array)
    runtimeAPI.client.bm_register_write(0, register.name, index, value)

def main(p4info_file_path, bmv2_file_path, runtimeAPI):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 s2 s3;
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
	#############################################################################
	writeIPRules(p4info_helper, ingress_sw=s1, dst_eth_addr="00:00:00:00:01:01", dst_ip="10.0.1.1", mask=32, port=1)
	writeIPRules(p4info_helper, ingress_sw=s1, dst_eth_addr="00:00:00:03:03:00", dst_ip="10.0.3.3", mask=32, port=2)
	writeIPRules(p4info_helper, ingress_sw=s2, dst_eth_addr="00:00:00:00:02:02", dst_ip="10.0.2.2", mask=32, port=1)
	writeIPRules(p4info_helper, ingress_sw=s2, dst_eth_addr="00:00:00:02:03:00", dst_ip="10.0.3.3", mask=32, port=2)
	writeIPRules(p4info_helper, ingress_sw=s3, dst_eth_addr="00:00:00:00:03:03", dst_ip="10.0.3.3", mask=32, port=1)
	writeIPRules(p4info_helper, ingress_sw=s3, dst_eth_addr="00:00:00:01:03:00", dst_ip="10.0.1.1", mask=32, port=2)
	writeIPRules(p4info_helper, ingress_sw=s3, dst_eth_addr="00:00:00:02:03:00", dst_ip="10.0.2.2", mask=32, port=3)

	#############################################################################

    # set meter
    runtimeAPI.do_meter_array_set_rates("meter_array_set_rates ingress_meter_stats 0.0000128:9000 0.0000128:9000")

    m = 0
    while True:
        print "------------"
        print m," minute"
        res_num = read_register(runtimeAPI, "r_reg", 0)
        flag = read_register(runtimeAPI, "f_reg", 0)
        print "res_num: ", res_num
        print "flag: ", flag
        if res_num >= 10:
            if flag >= 5:
                write_register(runtimeAPI, "f_reg", 0, flag+1)
            else:
                write_register(runtimeAPI, "f_reg", 0, 5)
        elif res_num < 10 and flag > 0:
            write_register(runtimeAPI, "f_reg", 0, flag-1)

        if flag > 0:
            print "Mode on..."
            for i in range(0, 65536):
                t_id = read_register(runtimeAPI, "reg_ingress", i)
                if t_id > 0:
                    write_register(runtimeAPI, "reg_ingress", i, t_id-1)
                    print "reg[",i,"] = ",t_id-1
        
        write_register(runtimeAPI, "r_reg", 0, 0) # clean r_reg every minute
        m += 1
        sleep(30)


    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    # parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser = runtime_CLI.get_parser()
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.p4.p4info.txt')
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


    standard_client, mc_client = utils.thrift_connect(
        args.thrift_ip, args.thrift_port,
        runtime_CLI.RuntimeAPI.get_thrift_services(args.pre)
    )

    runtime_CLI.load_json_config(standard_client, args.bmv2_json)
    runtimeAPI = runtime_CLI.RuntimeAPI(args.pre, standard_client, mc_client)
    main(args.p4info, args.bmv2_json, runtimeAPI)
