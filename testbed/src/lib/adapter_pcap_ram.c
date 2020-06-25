#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "include/adapter_pcap_ram.h"

adapter_t* adapter_init(const char* dir, const char* file) {
    adapter_t* ret = (adapter_t*)calloc(1, sizeof(adapter_t));

    char buf[MAX_FILE_LEN];
    FILE* input = fopen(strconcat(dir, file), "r");
    while (1) {
        if (fgets(buf, MAX_FILE_LEN, input) == NULL) {
            break;
        }

        buf[strlen(buf)-1] = '\0';
        strcpy(ret->filename[ret->file_num], strconcat(dir, buf));
        ret->file_num++;
    }
    fclose(input);

	char errbuf[PCAP_ERRBUF_SIZE];
	if ((ret->pcap = pcap_open_offline(ret->filename[0], errbuf)) == NULL) {
		LOG_ERR("cannot open %s (%s)\n", ret->filename[0], errbuf);
	}

    return ret;
}

void dumper_init(adapter_t* adapter, const char* dir, uint32_t hid) {
    char tmp[100];
    sprintf(tmp, "%s/processed_trace/host_%u.pcap", dir, hid);
    adapter->pcap_dumper = pcap_dump_open(adapter->pcap, tmp);
    if (adapter->pcap_dumper == NULL) {
        LOG_ERR("cannot open %s\n", tmp);
    }
}

void adapter_destroy(adapter_t* adapter) {
    pcap_close(adapter->pcap);
    if (adapter->pcap_dumper)
        pcap_dump_close(adapter->pcap_dumper);
}

int adapter_next(adapter_t* adapter, tuple_t* p, enum PACKET_STATUS* status) {
    const u_char* pkt; // raw packet
    struct pcap_pkthdr hdr;
	pkt = adapter_next_pkt(adapter, p, status, &hdr);
    if (pkt == NULL)
        return -1;
    else
        return 0;
}

 const u_char * adapter_next_pkt(adapter_t* adapter, tuple_t* p, enum PACKET_STATUS* status, struct pcap_pkthdr *hdr) {
     double pkt_ts; // packet timestamp
     int pkt_len; // packet snap length
     const u_char* pkt; // raw packet
     uint8_t pkt_data[MAX_CAPLEN];

     pkt = pcap_next(adapter->pcap, hdr);
     if (pkt == NULL) {
         LOG_MSG("%s complete\n", adapter->filename[adapter->file_cur]);
         adapter->file_cur++;
         if (adapter->file_cur < adapter->file_num) {
             pcap_close(adapter->pcap);
             char* file = adapter->filename[adapter->file_cur];
             char errbuf[PCAP_ERRBUF_SIZE];
             if ((adapter->pcap = pcap_open_offline(file, errbuf)) == NULL) {
                 LOG_ERR("cannot open %s (%s)\n", file, errbuf);
             }
             pkt = pcap_next(adapter->pcap, hdr);
             if (pkt == NULL) {
                 return NULL;
             }
         }
         else {
             return NULL;
         }
     }
     pkt_ts = (double)(*hdr).ts.tv_usec / 1000000 + (*hdr).ts.tv_sec;
     pkt_len = (*hdr).caplen < MAX_CAPLEN ? (*hdr).caplen : MAX_CAPLEN;
     memcpy(pkt_data, pkt, pkt_len);

     *status = decode(pkt_data, pkt_len, (*hdr).len, pkt_ts, p);
     return pkt;
 }

 void adapter_save(adapter_t* adapter, struct pcap_pkthdr* h, u_char *sp) {
     pcap_dump((u_char*)adapter->pcap_dumper, h, sp);
 }

