
parser start {
   return parse_ethernet;
}

header ethernet_t ethernet;
header omnimon_t omnimon;

parser parse_ethernet {
   extract(ethernet);
   extract(omnimon);
   return select(ethernet.etherType) {
    //    0x8100 : parse_vlan_tag;
       0x800 : parse_ipv4;
       default: ingress;
   }
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
    return ingress;
}

header udp_t udp;

parser parse_udp {
    extract(udp);
    return ingress;
}
