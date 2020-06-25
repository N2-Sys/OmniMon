#ifndef __ADAPTER_PCAP_RAM_H__
#define __ADAPTER_PCAP_RAM_H__

#include <pcap.h>
#include "include/config.h"
#include "include/packet_helper.h"
#include "packet.h"

typedef struct {

    int file_num, file_cur;
    char filename[MAX_FILE][MAX_FILE_LEN];

	pcap_t* pcap;
    pcap_dumper_t* pcap_dumper; 

} adapter_t;

adapter_t* adapter_init(const char* dir, const char* file);
void dumper_init(adapter_t* , const char*, uint32_t);
void adapter_destroy(adapter_t*);

int adapter_next(adapter_t* adapter, tuple_t* p, enum PACKET_STATUS* status);

const u_char * adapter_next_pkt(adapter_t* adapter, tuple_t* p, enum PACKET_STATUS* status, struct pcap_pkthdr *h);

void adapter_save(adapter_t* adapter, struct pcap_pkthdr* h, u_char *sp);

#endif
