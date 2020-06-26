#include "packet.h"
#include "include/packet_helper.h"

//SJB **

#define MAX_FILE (8192*8)
#define MAX_FILE_LEN 1024

typedef struct {

    int file_num, file_cur;
    char filename[MAX_FILE][MAX_FILE_LEN];
    char processed[MAX_FILE][MAX_FILE_LEN];
    pcap_t* pcap;
    pcap_dumper_t* pcap_dumper;

} adapter_t;

adapter_t* adapter_init(const char* dir, const char* file);
void adapter_destroy(adapter_t*);

const u_char * adapter_next(adapter_t* adapter, tuple_t* p, enum PACKET_STATUS* status, struct pcap_pkthdr *hdr);
//SJB