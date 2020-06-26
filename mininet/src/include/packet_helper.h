#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include "packet.h"
#include "include/util.h"

#ifndef __PACKET_H__
#define __PACKET_H__

#define MAX_CAPLEN 1500
#define ETH_LEN 14
#define IP_CHECK 0

enum PACKET_STATUS {
    STATUS_INIT = 0,            // initial state
    STATUS_VALID,               // valid packets
    // error status
    STATUS_NON_IP,              // not an IP packet
    STATUS_IP_NOT_FULL,         // IP not full packets
    STATUS_IP_VER_FAIL,         // IP version failed
    STATUS_IP_CHKSUM_FAIL,      // IP checksum failed
    STATUS_IP_FRAG,             // IP fragments
    STATUS_TCP_NOT_FULL,        // TCP header not full
    STATUS_UDP_NOT_FULL,        // UDP header not full
    STATUS_ICMP_NOT_FULL,       // ICMP header not full
    STATUS_UNDEFINED,           // (not used for now)
    STATUS_NON_GTP,             // not a valid GTP packet
    STATUS_NON_GPRS             // not a valid GPRS packet
};

struct PacketStat {
    uint64_t tot_pkt_cnt;           // total # of packets observed
    uint64_t tot_cap_byte_cnt;          // total # of bytes observed
    uint64_t tot_act_byte_cnt;          // total # of bytes observed
    uint64_t valid_pkt_cnt;         // # of valid packets
    uint64_t valid_cap_byte_cnt;        // # of valid bytes
    uint64_t valid_act_byte_cnt;        // # of valid bytes
    uint64_t non_ip_cnt;            // # of non-IP packets
    uint64_t ip_not_full_cnt;       // # of IP non-full packets
    uint64_t ip_ver_fail_cnt;       // # of IP version failed packets
    uint64_t ip_chksum_fail_cnt;    // # of IP checksum failed packets
    uint64_t ip_frag_cnt;           // # of IP fragments 
    uint64_t tcp_not_full_cnt;      // # of TCP-not-full packets
    uint64_t udp_not_full_cnt;      // # of UDP-not-full packets
    uint64_t icmp_not_full_cnt;     // # of ICMP-not-full packets
    uint64_t undefined_cnt;
    uint64_t non_gtp_cnt;
    uint64_t non_gprs_cnt;
    uint64_t used_time;
    double trace_start_ts;
    double trace_end_ts;
};

extern uint64_t seq_count;

void print_tuple(FILE* f, tuple_t* t);
void read_tuple(char*, tuple_t* t);

void report_final_stat();
void report_final_stat_file(const char* filename);
void reset_stat();

enum PACKET_STATUS decode(const uint8_t* pkt, uint32_t cap_len, uint32_t act_len, double ts, tuple_t* t);

extern char ip1[30];
extern char ip2[30];
/*
 * Convert IP (in network order) to string
 */
static inline char* ip2a(uint32_t ip, char* addr) {
    sprintf(addr, "%d.%d.%d.%d", ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) &
            0xff, (ip >> 24) & 0xff);
    return addr;
}


#endif
