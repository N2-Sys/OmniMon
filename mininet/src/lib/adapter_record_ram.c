#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "include/adapter_record_ram.h"
#include "include/config.h"
#include "include/packet_helper.h"

adapter_t* adapter_init(const char* dir, const char* file) {
    adapter_t* ret = (adapter_t*)calloc(1, sizeof(adapter_t));

    char buf[MAX_FILE_LEN];
    FILE* input = fopen(strconcat(dir, file), "r");
    //DEBUG
    if(input == NULL){
	LOG_ERR("pcap file open failed\n");	
	}
    char tmp[MAX_FILE_LEN];
    sprintf(tmp, "%s/processed_trace", dir);
    mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH| S_IXOTH);
    while (1) {
        if (fgets(buf, MAX_FILE_LEN, input) == NULL) {
            break;
        }
        buf[strlen(buf)-1] = '\0';
        sprintf(tmp, "%s/processed_trace/%s", dir, buf);
        strcpy(ret->processed[ret->file_num], tmp);
        strcpy(ret->filename[ret->file_num], strconcat(dir, buf));
        ret->file_num++;
    }
    fclose(input);

	char errbuf[PCAP_ERRBUF_SIZE];
	if ((ret->pcap = pcap_open_offline(ret->filename[0], errbuf)) == NULL) {
		LOG_ERR("cannot open %s (%s)\n", ret->filename[0], errbuf);
	}


    ret->pcap_dumper = pcap_dump_open(ret->pcap, ret->processed[0]);
    if (ret->pcap_dumper == NULL) {
        LOG_ERR("cannot open %s\n", ret->processed[0]); 
    }
    return ret;
}

void adapter_destroy(adapter_t* adapter) {
    pcap_close(adapter->pcap);
}

//SJB **
const u_char * adapter_next(adapter_t* adapter, tuple_t* p, enum PACKET_STATUS* status, struct pcap_pkthdr *hdr) {
    double pkt_ts; // packet timestamp
    int pkt_len; // packet snap length
    const u_char* pkt; // raw packet
    uint8_t pkt_data[MAX_CAPLEN];
    //struct pcap_pkthdr hdr;

    pkt = pcap_next(adapter->pcap, hdr);
    if (pkt == NULL) {
        //LOG_MSG("%s complete\n", adapter->filename[adapter->file_cur]);
        adapter->file_cur++;
        if (adapter->file_cur < adapter->file_num) {
            pcap_close(adapter->pcap);
            char* file = adapter->filename[adapter->file_cur];
	        char errbuf[PCAP_ERRBUF_SIZE];
	        if ((adapter->pcap = pcap_open_offline(file, errbuf)) == NULL) {
		        LOG_ERR("cannot open %s (%s)\n", file, errbuf);
            }
            
            pcap_dump_close(adapter->pcap_dumper);
            adapter->pcap_dumper = pcap_dump_open(adapter->pcap, adapter->processed[adapter->file_cur]);
            if (adapter->pcap_dumper == NULL) {
                LOG_ERR("cannot open %s\n", adapter->processed[adapter->file_cur]); 
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


//SJB


/*
int adapter_next(adapter_t* adapter, tuple_t* p) {
    if (adapter->cur == adapter->cnt) {
        return -1;
    }

    adapter->cur++;
    memcpy(p, adapter->ptr, sizeof(tuple_t));
    adapter->ptr += sizeof(tuple_t);

    return 0;
}
*/
