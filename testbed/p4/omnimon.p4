/****************************************
           OmniMon Demo
****************************************/

#include "tofino/intrinsic_metadata.p4"
#include "includes/headers.p4"
#include "includes/parser.p4"

header_type custom_metadata_t {
    fields {
        index1: 16;
        index2: 16;
    }
}

metadata custom_metadata_t custom_metadata;

action calc_index(base_start) {
    add(custom_metadata.index1, base_start, omnimon.switch_index1);
    add(custom_metadata.index2, base_start, omnimon.switch_index2);
}

table calc_index_table {
    reads {
        omnimon.epoch mask 0x3 : exact;
    }
    actions {
        calc_index;
    }
    size: 4;
}

/*** OmniMon Counters ***/

// We hide the Omnimon Counters due to Barefoot NDA


/*** Forward ***/

action set_egr(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}

action nop() {
}

table forward {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {
        set_egr;
        nop;
    }
    size: 1024;
}

/******************/

control ingress {
    apply(calc_index_table);
    apply(forward);
}

control egress {
}

