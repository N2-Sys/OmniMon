#!/usr/bin/env python2

import argparse
import cmd
from collections import Counter
import os
import sys
import struct
import json
from functools import wraps
import bmpy_utils as utils

from bm_runtime.standard import Standard
from bm_runtime.standard.ttypes import *
try:
    from bm_runtime.simple_pre import SimplePre
except:
    pass
try:
    from bm_runtime.simple_pre_lag import SimplePreLAG
except:
    pass

# user-configurable parameters related to topologic structure
switch_num = 3
default_ip = 'localhost'
default_port = 20001

def enum(type_name, *sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())

    @staticmethod
    def to_str(x):
        return reverse[x]
    enums['to_str'] = to_str

    @staticmethod
    def from_str(x):
        return enums[x]

    enums['from_str'] = from_str
    return type(type_name, (), enums)

PreType = enum('PreType', 'None', 'SimplePre', 'SimplePreLAG')

def get_parser():

    class ActionToPreType(argparse.Action):
        def __init__(self, option_strings, dest, nargs=None, **kwargs):
            if nargs is not None:
                raise ValueError("nargs not allowed")
            super(ActionToPreType, self).__init__(option_strings, dest, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            assert(type(values) is str)
            setattr(namespace, self.dest, PreType.from_str(values))

    parser = argparse.ArgumentParser(description='API for reading register values')
    parser.add_argument('--json', help='JSON description of P4 program',
                        type=str, action="store", default='./output/omnimon.json')
    parser.add_argument('--pre', help='Packet Replication Engine used by target',
                        type=str, choices=['None', 'SimplePre', 'SimplePreLAG'],
                        default=PreType.SimplePre, action=ActionToPreType)

    return parser

# services is [(service_name, client_class), ...]
def thrift_connect(thrift_ip, thrift_port, services):
    return utils.thrift_connect(thrift_ip, thrift_port, services)

def get_thrift_services(pre_type):
    services = [("standard", Standard.Client)]

    if pre_type == PreType.SimplePre:
        services += [("simple_pre", SimplePre.Client)]
    elif pre_type == PreType.SimplePreLAG:
        services += [("simple_pre_lag", SimplePreLAG.Client)]
    else:
        services += [(None, None)]

    return services

def read_register_from_switch(ip, port, pre):
    client, mc_client = thrift_connect(
        ip, port, get_thrift_services(pre)
    )

    # extract register values from switches
    flow_packets_counter_ig_index1_entries = client.bm_register_read_all(0, "flow_packets_counter_ig_index1")
    flow_packets_counter_ig_index2_entries = client.bm_register_read_all(0, "flow_packets_counter_eg_index2")
    flow_packets_counter_eg_index1_entries = client.bm_register_read_all(0, "flow_packets_counter_eg_index1")
    flow_packets_counter_eg_index2_entries = client.bm_register_read_all(0, "flow_packets_counter_eg_index2")

    # ack_packets_counter_eg_index1_entries = client.bm_register_read_all(0, "ack_packets_counter_eg_index2")
    # ack_packets_counter_eg_index2_entries = client.bm_register_read_all(0, "ack_packets_counter_eg_index2")
    # ack_packets_counter_ig_index1_entries = client.bm_register_read_all(0, "ack_packets_counter_ig_index1")
    # ack_packets_counter_ig_index2_entries = client.bm_register_read_all(0, "ack_packets_counter_ig_index2")
    # fin_packets_counter_eg_index1_entries = client.bm_register_read_all(0, "fin_packets_counter_eg_index1")
    # fin_packets_counter_eg_index2_entries = client.bm_register_read_all(0, "fin_packets_counter_eg_index2")
    # fin_packets_counter_ig_index1_entries = client.bm_register_read_all(0, "fin_packets_counter_ig_index1")
    # fin_packets_counter_ig_index2_entries = client.bm_register_read_all(0, "fin_packets_counter_ig_index2")
    # fix_payload_flow_packets_counter_eg_index1_entries = client.bm_register_read_all(0, "fix_payload_flow_packets_counter_eg_index1")
    # fix_payload_flow_packets_counter_eg_index2_entries = client.bm_register_read_all(0, "fix_payload_flow_packets_counter_eg_index2")
    # fix_payload_flow_packets_counter_ig_index1_entries = client.bm_register_read_all(0, "fix_payload_flow_packets_counter_ig_index1")
    # fix_payload_flow_packets_counter_ig_index2_entries = client.bm_register_read_all(0, "fix_payload_flow_packets_counter_ig_index2")
    # flow_size_counter_eg_index1_entries = client.bm_register_read_all(0, "flow_size_counter_eg_index1")
    # flow_size_counter_eg_index2_entries = client.bm_register_read_all(0, "flow_size_counter_eg_index2")
    # flow_size_counter_ig_index1_entries = client.bm_register_read_all(0, "flow_size_counter_ig_index1")
    # flow_size_counter_ig_index2_entries = client.bm_register_read_all(0, "flow_size_counter_ig_index2")
    # flow_version_counter_eg_index1_entries = client.bm_register_read_all(0, "flow_version_counter_eg_index1")
    # flow_version_counter_eg_index2_entries = client.bm_register_read_all(0, "flow_version_counter_eg_index2")
    # flow_version_counter_ig_index1_entries = client.bm_register_read_all(0, "flow_version_counter_ig_index1")
    # flow_version_counter_ig_index2_entries = client.bm_register_read_all(0, "flow_version_counter_ig_index2")
    # small_packets_counter_eg_index1_entries = client.bm_register_read_all(0, "small_packets_counter_eg_index1")
    # small_packets_counter_eg_index2_entries = client.bm_register_read_all(0, "small_packets_counter_eg_index2")
    # small_packets_counter_ig_index1_entries = client.bm_register_read_all(0, "small_packets_counter_ig_index1")
    # small_packets_counter_ig_index2_entries = client.bm_register_read_all(0, "small_packets_counter_ig_index2")
    # syn_ack_packets_counter_eg_index1_entries = client.bm_register_read_all(0, "syn_ack_packets_counter_eg_index1")
    # syn_ack_packets_counter_eg_index2_entries = client.bm_register_read_all(0, "syn_ack_packets_counter_eg_index2")
    # syn_ack_packets_counter_ig_index1_entries = client.bm_register_read_all(0, "syn_ack_packets_counter_ig_index1")
    # syn_ack_packets_counter_ig_index2_entries = client.bm_register_read_all(0, "syn_ack_packets_counter_ig_index2")
    # syn_packets_counter_eg_index1_entries = client.bm_register_read_all(0, "syn_packets_counter_eg_index1")
    # syn_packets_counter_eg_index2_entries = client.bm_register_read_all(0, "syn_packets_counter_eg_index2")
    # syn_packets_counter_ig_index1_entries = client.bm_register_read_all(0, "syn_packets_counter_ig_index1")
    # syn_packets_counter_ig_index2_entries = client.bm_register_read_all(0, "syn_packets_counter_ig_index2")

    # write values into files
    switch_id = port-default_port+1
    path = "../output/switch/"
    isexist = os.path.exists(path)
    if not isexist:
	os.makedirs(path)
    ingress_file_name = '../output/switch/s%d_ingress.txt' % (switch_id)
    egress_file_name = '../output/switch/s%d_egress.txt' % (switch_id)
    ingress_file = open(ingress_file_name, "wb+")
    egress_file = open(egress_file_name, "wb+")
    for index in range(len(flow_packets_counter_ig_index1_entries)):
        value = flow_packets_counter_ig_index1_entries[index]+flow_packets_counter_ig_index2_entries[index]
        #if value > 0: print "Success\n"
        pair = "%d: %d\n" % (index,value)
        ingress_file.write(pair)
    for index in range(len(flow_packets_counter_eg_index1_entries)):
        value = flow_packets_counter_eg_index1_entries[index]+flow_packets_counter_eg_index2_entries[index]
        #if value > 0: print "Success\n"
        pair = "%d: %d\n" % (index,value)
        egress_file.write(pair)
    ingress_file.close()
    egress_file.close()


def read_register_from_all_switches():
    args = get_parser().parse_args()
    ip, port, pre = default_ip, default_port, args.pre
    for i in range(switch_num):
        read_register_from_switch(ip,port+i,pre)

if __name__ == '__main__':
    read_register_from_all_switches()

