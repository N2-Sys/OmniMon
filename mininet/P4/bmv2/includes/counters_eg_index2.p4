/*** OmniMon Counters ***/

/*** Flow version records ***/
register flow_version_counter_eg_index2 {
    width : 8;
    instance_count : TOTAL_REG_SIZE;
}

action set_flow_version_eg_index2() {
    register_write(flow_version_counter_eg_index2, custom_metadata.index1, omnimon.version);
}

table set_flow_version_table_eg_index2 {
    actions {
        set_flow_version_eg_index2;
    }
    size: 1;
}

/*** Flow packets counters ***/
register flow_packets_counter_eg_index2 {
    width : 32;
    instance_count : TOTAL_REG_SIZE;
}

header_type flow_packets_counter_eg_index2_metadata_t {
    fields {
        value : 32;
    }
}
metadata flow_packets_counter_eg_index2_metadata_t flow_packets_counter_eg_index2_md;

action set_flow_packets_eg_index2() {
    register_read(flow_packets_counter_eg_index2_md.value, flow_packets_counter_eg_index2, custom_metadata.index1);
    add(flow_packets_counter_eg_index2_md.value, flow_packets_counter_eg_index2_md.value, 1);
    register_write(flow_packets_counter_eg_index2, custom_metadata.index1, flow_packets_counter_eg_index2_md.value);
}

table set_flow_packets_table_eg_index2 {
    actions {
        set_flow_packets_eg_index2;
    }
    default_action : set_flow_packets_eg_index2();
}

/*** Flow packets size ***/
register flow_size_counter_eg_index2 {
    width : 32;
    instance_count : TOTAL_REG_SIZE;
}

header_type flow_size_counter_eg_index2_metadata_t {
    fields {
        value : 32;
    }
}
metadata flow_size_counter_eg_index2_metadata_t flow_size_counter_eg_index2_md;

action set_flow_size_eg_index2() {
    register_read(flow_size_counter_eg_index2_md.value, flow_size_counter_eg_index2, custom_metadata.index1);
    add(flow_size_counter_eg_index2_md.value, flow_size_counter_eg_index2_md.value, ipv4.totalLen);
    register_write(flow_size_counter_eg_index2, custom_metadata.index1, flow_size_counter_eg_index2_md.value);
}

table set_flow_size_table_eg_index2 {
    actions {
        set_flow_size_eg_index2;
    }
    size: 1;
}

/*** Syn packets counter ***/
register syn_packets_counter_eg_index2 {
    width : 8;
    instance_count : TOTAL_REG_SIZE;
}

header_type syn_packets_counter_eg_index2_metadata_t {
    fields {
        value : 8;
    }
}
metadata syn_packets_counter_eg_index2_metadata_t syn_packets_counter_eg_index2_md;

action set_tcp_syn_packets_eg_index2() {
    register_read(syn_packets_counter_eg_index2_md.value, syn_packets_counter_eg_index2, custom_metadata.index1);
    add(syn_packets_counter_eg_index2_md.value, syn_packets_counter_eg_index2_md.value, 1);
    register_write(syn_packets_counter_eg_index2, custom_metadata.index1, syn_packets_counter_eg_index2_md.value);
}

table set_tcp_syn_packets_table_eg_index2 {
    actions {
        set_tcp_syn_packets_eg_index2;
    }
    size: 1;
}

control apply_set_tcp_syn_packets_table_eg_index2 {
    if (tcp.ctrl == 0x1) {
        apply(set_tcp_syn_packets_table_eg_index2);
    }
}

/*** Ack packets counter ***/
register ack_packets_counter_eg_index2 {
    width : 32;
    instance_count : TOTAL_REG_SIZE;
}

header_type ack_packets_counter_eg_index2_metadata_t {
    fields {
        value : 32;
    }
}
metadata ack_packets_counter_eg_index2_metadata_t ack_packets_counter_eg_index2_md;

action set_tcp_ack_packets_eg_index2() {
    register_read(ack_packets_counter_eg_index2_md.value, ack_packets_counter_eg_index2, custom_metadata.index1);
    add(ack_packets_counter_eg_index2_md.value, ack_packets_counter_eg_index2_md.value, 1);
    register_write(ack_packets_counter_eg_index2, custom_metadata.index1, ack_packets_counter_eg_index2_md.value);
}

table set_tcp_ack_packets_table_eg_index2 {
    actions {
        set_tcp_ack_packets_eg_index2;
    }
    size: 1;
}

control apply_set_tcp_ack_packets_table_eg_index2 {
    if (tcp.ctrl == 0x8) {
        apply(set_tcp_ack_packets_table_eg_index2);
    }
}

/*** Syn/Ack packets counter ***/
register syn_ack_packets_counter_eg_index2 {
    width : 8;
    instance_count : TOTAL_REG_SIZE;
}

header_type syn_ack_packets_counter_eg_index2_metadata_t {
    fields {
        value : 8;
    }
}
metadata syn_ack_packets_counter_eg_index2_metadata_t syn_ack_packets_counter_eg_index2_md;

action set_tcp_syn_ack_packets_eg_index2() {
    register_read(syn_ack_packets_counter_eg_index2_md.value, syn_ack_packets_counter_eg_index2, custom_metadata.index1);
    add(syn_ack_packets_counter_eg_index2_md.value, syn_ack_packets_counter_eg_index2_md.value, 1);
    register_write(syn_ack_packets_counter_eg_index2, custom_metadata.index1, syn_ack_packets_counter_eg_index2_md.value);
}

table set_tcp_syn_ack_packets_table_eg_index2 {
    actions {
        set_tcp_syn_ack_packets_eg_index2;
    }
    size: 1;
}

control apply_set_tcp_syn_ack_packets_table_eg_index2 {
    if (tcp.ctrl == 0x9) {
        apply(set_tcp_syn_ack_packets_table_eg_index2);
    }
}

/*** Fin packets counter ***/
register fin_packets_counter_eg_index2 {
    width : 8;
    instance_count : TOTAL_REG_SIZE;
}

header_type fin_packets_counter_eg_index2_metadata_t {
    fields {
        value : 8;
    }
}
metadata fin_packets_counter_eg_index2_metadata_t fin_packets_counter_eg_index2_md;

action set_tcp_fin_packets_eg_index2() {
    register_read(fin_packets_counter_eg_index2_md.value, fin_packets_counter_eg_index2, custom_metadata.index1);
    add(fin_packets_counter_eg_index2_md.value, fin_packets_counter_eg_index2_md.value, 1);
    register_write(fin_packets_counter_eg_index2, custom_metadata.index1, fin_packets_counter_eg_index2_md.value);
}

table set_tcp_fin_packets_table_eg_index2 {
    actions {
        set_tcp_fin_packets_eg_index2;
    }
    size: 1;
}

control apply_set_tcp_fin_packets_table_eg_index2 {
    if (tcp.fin == 0x1) {
        apply(set_tcp_fin_packets_table_eg_index2);
    }
}

/*** small packets counter ***/
register small_packets_counter_eg_index2 {
    width : 16;
    instance_count : TOTAL_REG_SIZE;
}

#define FIX_SIZE 40

header_type small_packets_counter_eg_index2_metadata_t {
    fields {
        value : 16;
    }
}
metadata small_packets_counter_eg_index2_metadata_t small_packets_counter_eg_index2_md;

action set_telnet_small_packets_eg_index2() {
    register_read(small_packets_counter_eg_index2_md.value, small_packets_counter_eg_index2, custom_metadata.index1);
    add(small_packets_counter_eg_index2_md.value, small_packets_counter_eg_index2_md.value, 1);
    register_write(small_packets_counter_eg_index2, custom_metadata.index1, small_packets_counter_eg_index2_md.value);
}

table set_telnet_small_packets_table_eg_index2 {
    actions {
        set_telnet_small_packets_eg_index2;
    }
    size: 1;
}

control apply_set_telnet_small_packets_table_eg_index2 {
    if (ipv4.totalLen == FIX_SIZE and tcp.dstPort == 23) {
        apply(set_telnet_small_packets_table_eg_index2);
    }
}
