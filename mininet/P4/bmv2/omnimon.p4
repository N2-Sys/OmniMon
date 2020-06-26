/****************************************
           OmniMon Demo
****************************************/

#include "includes/headers.p4"
#include "includes/parser.p4"

#define PORT_NUM 32
#define VERSION_NUM 4
#define REGISTER_SIZE 512
#define TOTAL_REG_SIZE 65536

action calc_index(base_start) {
    add(custom_metadata.index1, base_start, omnimon.index1);
    add(custom_metadata.index2, base_start, omnimon.index2);
}

table calc_index_table {
    reads {
        omnimon.version mask 0x3 : exact;
        standard_metadata.ingress_port : exact;
    }
    actions {
        calc_index;
    }
    size: 128;
}
/*** OmniMon Counters ***/

#include "includes/counters_ig_index1.p4"
#include "includes/counters_ig_index2.p4"
#include "includes/counters_eg_index1.p4"
#include "includes/counters_eg_index2.p4"


/*** Fixed Payload Flow packets counters ***/
#define FIX_PAYLOAD_FLOW_PKTS_COUNTER(pipe, id) \
register fix_payload_flow_packets_counter_##pipe##_index##id { \
    width : 16; \
    instance_count : TOTAL_REG_SIZE; \
} \
\
header_type fix_payload_flow_packets_counter_##pipe##_index##id##_metadata_t { \
    fields { \
        value : 16; \
    } \
} \
metadata fix_payload_flow_packets_counter_##pipe##_index##id##_metadata_t fix_payload_flow_packets_counter_##pipe##_index##id##_md; \
\
action set_fix_payload_flow_packets_##pipe##_index##id() { \
    register_read(fix_payload_flow_packets_counter_##pipe##_index##id##_md.value, fix_payload_flow_packets_counter_##pipe##_index##id##, custom_metadata.index1); \
    add(fix_payload_flow_packets_counter_##pipe##_index##id##_md.value, fix_payload_flow_packets_counter_##pipe##_index##id##_md.value, 1); \
    register_write(fix_payload_flow_packets_counter_##pipe##_index##id##, custom_metadata.index1, fix_payload_flow_packets_counter_##pipe##_index##id##_md.value); \
} \
\
table set_fix_payload_flow_packets_table_##pipe##_index##id { \
    actions { \
        set_fix_payload_flow_packets_##pipe##_index##id##; \
    } \
    size: 1; \
}

FIX_PAYLOAD_FLOW_PKTS_COUNTER(ig, 1)
FIX_PAYLOAD_FLOW_PKTS_COUNTER(ig, 2)
FIX_PAYLOAD_FLOW_PKTS_COUNTER(eg, 1)
FIX_PAYLOAD_FLOW_PKTS_COUNTER(eg, 2)

/*** Forward ***/

action set_egr(egress_spec) {
    modify_field(standard_metadata.egress_spec, egress_spec);
}

action nop() {
}

table forward {
    reads {
        //standard_metadata.ingress_port : exact;
        ethernet.dstAddr : exact;
    }
    actions {
        set_egr;
        nop;
    }
    size: PORT_NUM;
}

table forward_to_controller {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        set_egr;
        nop;
    }
    default_action : nop();
}

/**** drop ****/

//action _drop() {
//    drop();
//}

//table drop_table {
//    actions {
//     _drop; 
//     }
//    size: 1;
//}

register debug_index {
    width : 16;
    instance_count : 1;
}

register debug {
    width : 16;
    instance_count : 10;
}

header_type debug_meta_t {
    fields {
        pkt_cnt : 32;
        value : 16;
        index : 16;
    }
}
metadata debug_meta_t debug_meta;

action read_debug_index() {
    register_read(debug_meta.index, debug_index, 0);
}

table read_debug_index_tbl {
    actions { read_debug_index; }
    default_action : read_debug_index();
}

action write_debug_index() {
    register_write(debug_index, 0, debug_meta.index+1);
}

table write_debug_index_tbl {
    actions { write_debug_index; }
    default_action : write_debug_index();
}

action write_debug() {
    register_write(debug, debug_meta.index, omnimon.index1);
}

table write_debug_tbl {
    actions { write_debug; }
    default_action : write_debug();
} 

register omnimon_pkt_cnt {
    width : 32;
    instance_count : 1;
}

action read_omnimon_pkt_cnt() {
   register_read(debug_meta.pkt_cnt, omnimon_pkt_cnt, 0);
}

action write_omnimon_pkt_cnt() {
   register_write(omnimon_pkt_cnt, 0, debug_meta.pkt_cnt+1);
}

table read_omnimon_pkt_cnt_tbl {
    actions { read_omnimon_pkt_cnt; }
    default_action : read_omnimon_pkt_cnt();
}

table write_omnimon_pkt_cnt_tbl {
    actions { write_omnimon_pkt_cnt; }
    default_action : write_omnimon_pkt_cnt();
}

/******************/

control ingress {
    if (valid(omnimon)) {
        // for debug
        //apply(read_debug_index_tbl);
        //apply(write_debug_index_tbl);
        //apply(write_debug_tbl);
        apply(read_omnimon_pkt_cnt_tbl);
        apply(write_omnimon_pkt_cnt_tbl);

        apply(set_flow_packets_table_ig_index1);
        apply(set_flow_packets_table_ig_index2);
    }
    apply(forward);
    apply(forward_to_controller);
}

control egress {
    if (valid(omnimon)) {
        apply(set_flow_packets_table_eg_index1);
        apply(set_flow_packets_table_eg_index2);
    }
}

