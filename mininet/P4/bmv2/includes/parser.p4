parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        0 : parse_omnimon;
        default : parse_ipv4;
    }
}

header omnimon_t omnimon;

parser parse_omnimon {
    extract(omnimon);
    set_metadata(custom_metadata.index1, omnimon.index1);
    set_metadata(custom_metadata.index2, omnimon.index2);
    return parse_ipv4;
}

#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17

header ipv4_t ipv4;

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        IP_PROTOCOLS_TCP : parse_tcp;
        IP_PROTOCOLS_UDP : parse_udp;
        default: ingress;
    }
}

header tcp_t tcp;

parser parse_tcp {
    extract(tcp);
    extract(l4_payload);
    //set_metadata(custom_metadata.tcpctrl, tcp.ctrl);
    return ingress;
}

header udp_t udp;

parser parse_udp {
    extract(udp);
    extract(l4_payload);
    return ingress;
}
