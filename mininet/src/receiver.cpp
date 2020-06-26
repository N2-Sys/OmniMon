// chenxiang, 2020/06/24

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string.h>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>

#include <time.h>
#include <pcap.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
using namespace std;

/* Ethernet addresses are 6 bytes */
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet {
    uint8_t dstAddr[ETHER_ADDR_LEN]; /* Destination host address */
    uint8_t srcAddr[ETHER_ADDR_LEN]; /* Source host address */
    uint16_t ether_type; /* IP? ARP? RARP? etc */
};

#define SIZE_OMNIMON 9

/* Omnimon header */
struct sniff_omnimon {
    uint32_t host_index; // 4 bytes
    uint8_t epoch;       // 1 byte
    uint16_t index1;     // 2 bytes
    uint16_t index2;     // 2 bytes
};

/* IP header */
struct sniff_ip {
    uint8_t ip_vhl;      /* version << 4 | header length >> 2 */
    uint8_t ip_tos;      /* type of service */
    uint16_t ip_len;     /* total length */
    uint16_t ip_id;      /* identification */
    uint16_t ip_off;     /* fragment offset field */
    uint8_t ip_ttl;      /* time to live */
    uint8_t protocol;    /* protocol */
    uint16_t ip_sum;     /* checksum */
    uint32_t srcAddr;    /* source and dest address */
    uint32_t dstAddr;    
};

/* TCP header */
struct sniff_tcp { 
    uint16_t srcPort; 
    uint16_t dstPort; 
    uint8_t seqNO[4]; 
    uint8_t ackNO[4]; 
    uint8_t headerLen; 
    uint8_t flags; 
    uint8_t window[2];  
    uint8_t checksum[2];  
    uint8_t urgentPointer[2]; 
};

/* UDP header */
struct sniff_udp { 
    uint16_t srcPort; 
    uint16_t dstPort; 
    uint16_t len;
    uint16_t checksum;
};

int omnimon_cnt = 0;
string fname;
map<uint32_t, uint32_t> omnimon_dict;
map<uint32_t, uint32_t>::iterator iter;

void break_handler(int sig=0){
    cout << "\nTotal: " << omnimon_cnt << " OmniMon packets." << endl;
    ofstream outfile;
    outfile.open(fname, ios::out | ios::trunc);
    cout << "Open " << fname << " successfully" << endl;
    map<uint32_t, uint32_t>::iterator loop_iter;
    for (loop_iter = omnimon_dict.begin(); loop_iter != omnimon_dict.end(); loop_iter++) {
        uint32_t key = loop_iter->first;
        uint32_t value = loop_iter->second;
        outfile << key << " " << value << endl;
    }
    outfile.close();
    exit(0);
}

int main(int argc, char **argv) {
    // update output file name based on input host id
    if (argc != 2) {
        cout << "Error: require host name!" << endl;
        cout << "e.g., in h1, you should execute the following command: ./receiver 1" << endl;
        return 0;
    }
    char* host_id = argv[1];
    string host_id_str(host_id);
    fname = "../output/hosts/dst_1_"+host_id_str+".txt";

    // setup signal
    signal(SIGINT, break_handler);

    // setup libpcap
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = -1; /* In milliseconds, -1 means no timeout */
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    handle = pcap_open_live(
            device,
            BUFSIZ,
            packet_count_limit,
            timeout_limit,
            error_buffer
        );

    clock_t start = clock();

    // sniff packets
    while (true) {
        clock_t now = clock();
        double diff = (double)((now-start)/CLOCKS_PER_SEC);
        if (diff >= 20) break_handler();

        const u_char *packet = pcap_next(handle, &packet_header);
        if (packet == NULL) {
            continue;
        } else cout << "receive a packet" << endl; 
        const struct sniff_ethernet *ethernet; /* The ethernet header */
        const struct sniff_omnimon *omnimon; /* The omnimon header */
        //const struct sniff_ip *ip; /* The IP header */
        //const struct sniff_tcp *tcp; /* The TCP header */
        //const struct sniff_udp *udp; /* The UDP header */
        ethernet = (struct sniff_ethernet*)(packet);
        // printf("Parsing Omnimon header\n");

        if (ethernet->ether_type == 0) {
            cout << "the packet is an omnimon packet\n" << endl;
            omnimon_cnt ++;
            omnimon = (struct sniff_omnimon*)(packet+sizeof(struct sniff_ethernet));
            // insert omnimon packet into dict
            uint32_t key = (uint32_t)ntohl(omnimon->host_index);
            cout << "host_index:" << key << endl;
            iter = omnimon_dict.find(key);
            if (iter != omnimon_dict.end()) {
                omnimon_dict[key]++;
            } else {
                omnimon_dict[key] = 1;
            }
        }

    }

    return 0;
}
