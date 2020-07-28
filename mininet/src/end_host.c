#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_ring.h>

#include <netinet/in.h>
#include <pcap.h>

#include "include/util.h"
#include "include/ringbuffer.h"
#include "include/packet_helper.h"
#include "include/config.h"

#include <semaphore.h>
#include "host.h"
#include "include/adapter_record_ram.h"
#include "include/hash.h"


#include "packet.h"

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



extern conf_t* conf;
pthread_t thread;
pthread_t host_thread;
sem_t sem;
msg_t send_msg;
msg_t recv_msg;

uint32_t* index1 = NULL;
uint32_t* index2 = NULL;
uint32_t* used = NULL;
uint32_t n_index = 0;
uint32_t index_ptr = 0;

uint64_t* version_start = NULL;
uint64_t* version_recv = NULL;
uint32_t max_version = 1024;

struct RingBuffer * ring = NULL;

ominimon_header_t to_net;
struct ether_header e_h;
void process_host_send_pkt(char* pkt,char*processed_pkt,int len, ominimon_header_t *o_header){
    to_net.index1 = htons(o_header->index1);
    to_net.index2 = htons(o_header->index2);
    to_net.version = o_header->version;
    to_net.position = htonl(o_header->position);
    memcpy(&e_h,pkt,sizeof(e_h));

    //LOG_MSG("omnimon: %u,%u,%u,%u\n",o_header->position,o_header->version,o_header->index1,o_header->index2);
    memset(processed_pkt, 0, MAX_HOST_DATA);
    memcpy(processed_pkt, pkt, sizeof(struct ether_header)); //ether header
    //LOG_MSG("ether: %u,%u,%u,%u,%u,%u\n",e_h.ether_dhost[0],e_h.ether_dhost[1],e_h.ether_dhost[2],e_h.ether_dhost[3],e_h.ether_dhost[4],e_h.ether_dhost[5]);
    memcpy(processed_pkt + sizeof(struct ether_header), &to_net, sizeof(struct ominimon_header));
    memcpy(processed_pkt + sizeof(struct ominimon_header) + sizeof(struct ether_header), pkt + sizeof(struct ether_header), len - sizeof(struct ether_header)); //other
}

struct RingBuffer* host_ring = NULL;
host_msg_t host_send_msg;
host_msg_t host_recv_msg;

void* host_io_thread(void *arg){
    host_msg_t host_send_msg;
    host_msg_t host_recv_msg;
    host_msg_t host_ring_msg;
    const u_char* host_recv_pkt;
    pcap_t *p;
    struct pcap_pkthdr *pcap_hdr;
    struct ominimon_header o_header;
    int len;
    char pkt[MAX_HOST_DATA];
    char processed_pkt[MAX_HOST_DATA];
    char err_buf[PCAP_ERRBUF_SIZE]; // pcap error buffer
    pcap_t* handle = pcap_init(err_buf);
    sem_post(&sem);

    host_t* host = (host_t*)arg;
    ingress_flow_metric_t* ig_data = NULL;

    while(1){
        if (read_ringbuffer(host_ring, &host_ring_msg) == 0){
            if (host_ring_msg.type == MSG_END)
                break;
            usleep(400);
            msg_decode_host_data(pkt, &len, &host_ring_msg, &o_header);
            process_host_send_pkt(pkt,processed_pkt,len,&o_header);
	pcap_sendpacket(handle,processed_pkt,len+sizeof(struct ominimon_header));
        }

        // parsing incoming packets
        if (pcap_next_ex(handle, &pcap_hdr, &host_recv_pkt) == 1){
            // parse packet
            const struct sniff_ethernet *ethernet; /* The ethernet header */
            const struct sniff_omnimon *omnimon; /* The omnimon header */
            const struct sniff_ip *ip; /* The IP header */
            const struct sniff_tcp *tcp; /* The TCP header */
            const struct sniff_udp *udp; /* The UDP header */
            ethernet = (struct sniff_ethernet*)(host_recv_pkt);
            //LOG_MSG("Parsing Omnimon header\n");
            omnimon = (struct sniff_omnimon*)(host_recv_pkt+sizeof(struct sniff_ethernet));
            //LOG_MSG("Parsing ether: %d,%d,%d,%d,%d,%d",ethernet->srcAddr[0],ethernet->srcAddr[1],ethernet->srcAddr[2],ethernet->srcAddr[3],ethernet->srcAddr[4],ethernet->srcAddr[5]);
            //LOG_MSG("Parsing IPv4 header\n");
            ip = (struct sniff_ip*)(host_recv_pkt+sizeof(struct sniff_ethernet)+sizeof(struct sniff_omnimon));
            uint16_t srcPort, dstPort;
            //LOG_MSG("Protocol: %u\n", (unsigned int)ip->protocol);
            if (ip->protocol == 6) {
              //  LOG_MSG("Parsing TCP header\n");
                tcp = (struct sniff_tcp*)((uint8_t*)ip+(ip->ip_len<<2));
                srcPort = tcp->srcPort;
                dstPort = tcp->dstPort;
            } else if (ip->protocol == 17) {
                //LOG_MSG("Parsing UDP header\n");
                udp = (struct sniff_udp*)((uint8_t*)ip+(ip->ip_len<<2));
                srcPort = tcp->srcPort;
                dstPort = tcp->dstPort;
            }

            // decode information
            tuple_t* t = (tuple_t*)malloc(sizeof(tuple_t));
            memset(t, 0, sizeof(tuple_t));
            t->key.src_ip = ip->srcAddr;
            t->key.dst_ip = ip->dstAddr;
            t->key.proto = ip->protocol;
            t->key.src_port = srcPort;
            t->key.dst_port = dstPort;
            t->byte = ntohs(ip->ip_len);
            uint8_t epoch = omnimon->epoch;
            uint32_t host_index = ntohl(omnimon->host_index);

            // update hashtable
            if (unlikely(epoch > host->last_version)) { // hybrid sync protocol
                host->last_version = epoch;
            }
            ig_data = host->ingress_flow_data+host_index;
            if (ig_data->pkt_cnt == 0) { // empty
                memcpy((uint8_t *)(host->ingress_flow_key+host_index), (uint8_t *)&t, sizeof(flow_key_t));
                ig_data->pkt_cnt = 1;
                ig_data->byte_cnt = t->byte;
                ig_data->epoch = epoch;
            } else {
                if (epoch == ig_data->epoch) { // hit in the same epoch
                    ig_data->pkt_cnt += 1;
                    ig_data->byte_cnt += t->byte;
                }
                else { // move into the next epoch
                    ig_data->pkt_cnt = 1;
                    ig_data->byte_cnt = t->byte;
                    ig_data->epoch = epoch;
                }
            }
        }
        /***********************/
    }
    LOG_MSG("Inter_host IO thread end\n");
}


void * io_thread(void *arg) {
    msg_t send_msg;
    msg_t recv_msg;
    large_msg_t large_recv_msg;
    host_msg_t host_msg;
    int is_end = 0;
    uint32_t version;
    host_t* host = (host_t*)arg;
    send_msg.host_id = host->id;
    send_msg.type = MSG_NEW_FLOW;
    zmq_host_send(host->channel, &send_msg);
    zmq_host_recv_large(host->channel, &large_recv_msg);
    LOG_MSG("Receive message from controller. length:%u\n",large_recv_msg.size);
    n_index = MAX_HOST_INDEX;
    msg_decode_new_flow_res(index1, index2, &n_index, &large_recv_msg);
    zmq_host_recv(host->channel, &recv_msg); // wait controller to notify start
    LOG_MSG("Receive notify_start message from controller\n");
    sem_post(&sem);
    msg_t ring_msg;
    while (1) {
        // if (read_ringbuffer(rb1, &recv_msg) == 0) {
        if (read_ringbuffer(ring, &ring_msg) == 0) {
            switch (ring_msg.type) {
                case MSG_SYNC:
                    msg_decode_sync(&version, &ring_msg);
                    zmq_host_send(host->channel, &ring_msg);
                    if (version < max_version) {
                        version_start[version] = now_us();
                    }
                    break;
                case MSG_NEW_FLOW:
                    break;

                case MSG_END:
                    is_end = 1;
                    break;
                default:
                    LOG_WARN("should not be here\n");
                    break;
            }
        }
        if (zmq_host_recv_nowait(host->channel, &recv_msg) == 0) {
            switch (recv_msg.type) {
                case MSG_SYNC:
                    msg_decode_sync(&version, &recv_msg);
                    if (version < max_version) {
                        version_recv[version] = now_us();
                    }
                    if (version > host->last_version) {
                        host->last_version = version;
                    }
                    break;
                case MSG_NEW_FLOW:
                    break;
                case MSG_END:
                    is_end = 1;
                    break;
                default:
                    LOG_WARN("should not be here\n");
                    break;
            }
        }

        if (is_end) {
            LOG_MSG("Controller_host IO thread end\n");
            break;
        }
    }
}

void allocate_new_flow_search(tuple_t* t, uint32_t* r_index1, uint32_t* r_index2) {
    uint32_t r = 0;
    uint32_t min_used = used[0];
    for (uint32_t i=1; i<n_index; i++) {
        if (used[i] < min_used) {
            min_used = used[i];
            r = i;
        }
    }
    used[r]++;
    *r_index1 = index1[r];
    *r_index2 = index2[r];
}

void allocate_new_flow_2choice(tuple_t* t, uint32_t* r_index1, uint32_t* r_index2) {
    uint64_t key = now_us();
    uint32_t r1 = (uint32_t )MurmurHash64A(&key, sizeof(uint64_t), 3) % n_index;
    key = now_us();
    uint32_t r2 = (uint32_t )MurmurHash64A(&key, sizeof(uint64_t), 3) % n_index;

    uint32_t r = r1;
    if (used[r1] > used[r2]) {
        r = r2;
    }
    used[r]++;
    *r_index1 = index1[r];
    *r_index2 = index2[r];
}

void allocate_new_flow_rr(tuple_t* t, uint32_t* r_index1, uint32_t* r_index2) {
    uint32_t r = (index_ptr++) % n_index;
    used[r]++;
    
    *r_index1 = index1[r];
    *r_index2 = index2[r];
}

uint32_t count = 0;
struct ether_header eh_path;
void compute_path(uint8_t src,uint8_t dst,uint8_t *s1,uint8_t *s2,uint8_t *s3){
    switch(src){
        case 1:
            if(dst == 2){
                *s1 = 1;
            }
            else{
                *s1 = 1;
                *s2 = 3;
                *s3 = 2;
            }
            break;
        case 2:
            if(dst == 1){
                *s1 = 1;
            }
            else{
                *s1 = 1;
                *s2 = 3;
                *s3 = 2;
            }
            break;

        case 3:
            if(dst == 4){
                *s1 = 2;
            }
            else{
                *s1 = 2;
                *s2 = 3;
                *s3 = 1;
            }

            break;
        case 4:
            if(dst == 3){
                *s1 = 2;
            }
            else{
                *s1 = 2;
                *s2 = 3;
                *s3 = 1;
            }
            break;
        default:
            break;
    }
}

flow_metric* host_process_packet(host_t* host, tuple_t* t, const u_char *pkt, int pkt_len) {
    void* data = NULL;
    flow_metric* ret_data = NULL;
    struct ominimon_header o_header;
    memcpy(&eh_path,pkt,sizeof(struct ether_header));
    uint32_t version = (uint32_t)(t->pkt_ts*1000/host->interval_len);
    if (unlikely(host->start_version == 0)) {
        host->start_version = version;
    }
    version = version - host->start_version;
    if (unlikely(version > host->last_version)) {
        host_print(host, host->last_version);
        host->last_version = version;
        msg_encode_sync(version, &send_msg);
        // while (rte_ring_sp_enqueue(ring, &send_msg) != 0) {}
        while (write_ringbuffer(ring, &send_msg, sizeof(msg_t)) < 0) {}
        host_reset(host);
    }

    host->interval_cnt++;

    // LOG_MSG("%u\n", host->interval_cnt);
    int ret = rte_hash_lookup_data(host->hash_table, t, &data);
    if (ret >= 0) {
        ret_data = (flow_metric*)data;
        if (version == ret_data->version) {
            ret_data->pkt_cnt += 1;
            ret_data->byte_cnt += t->byte;
        }
        else {
            ret_data->pkt_cnt = 1;
            ret_data->byte_cnt = t->byte;
            ret_data->version = version;
        }
    o_header.version = ret_data->version;
    o_header.position = ret_data->position;
    o_header.index1 = ret_data->index1;
    o_header.index2 = ret_data->index2;
    }
    else if (ret == -ENOENT) {
        if (host->cur_n >= host->max_n) {
            LOG_WARN("Reach max flow\n");
            return NULL;
            // break;
        }
        ret_data = host->flow_data+host->cur_n;
        ret_data->pkt_cnt = 1;
        ret_data->byte_cnt = t->byte;
        ret_data->version = version;
        allocate_new_flow_rr(t, &ret_data->index1, &ret_data->index2);
	compute_path(eh_path.ether_shost[5],eh_path.ether_dhost[5],&(ret_data->s1),&(ret_data->s2),&(ret_data->s3));
        ret_data->dst = eh_path.ether_dhost[5];
	ret = rte_hash_add_key_data(host->hash_table, t, ret_data);
        if (ret != 0) {
            LOG_MSG("RTE Hash add error\n");
        }
        int32_t position;
        ret = rte_hash_lookup_bulk(host->hash_table, (const void**)&t, 1, &position);
        if (ret != 0) {
            LOG_MSG("RTE lookup position error\n");
        }
        ret_data->position = position;
        host->cur_n += 1;
        o_header.version = ret_data->version;
        o_header.position = ret_data->position;
        o_header.index1 = ret_data->index1;
        o_header.index2 = ret_data->index2;
    }
    else {
        LOG_MSG("Lookup fail %d\n", ret);
    }

    msg_encode_host_data(pkt,pkt_len,&host_send_msg,o_header);
    // while(rte_ring_sp_enqueue(host_ring,&host_send_msg) != 0);
    if (write_ringbuffer(host_ring, &host_send_msg, sizeof(host_msg_t)) != 0)
    LOG_MSG("ring buffer full\n");
    return ret_data;
}

void init_dpdk(char* args) {
    size_t max_eal_argc = 100;
    char eal_argv0[] = "";
    char** eal_argv = (char**)calloc(max_eal_argc, sizeof(char*));
    eal_argv[0] = eal_argv0;
    int eal_argc = 1;
    if (strlen(args) > 0) {
        char* tok = strtok(args, " ");
        while (tok != NULL && eal_argc < max_eal_argc) {
            eal_argv[eal_argc++] = tok;
            tok = strtok(NULL, " ");
        }
    }
    int ret = rte_eal_init(eal_argc, eal_argv);
    if (ret < 0) {
        free(eal_argv);
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    }
    free(eal_argv);

    unsigned lcore_id;/*
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        LOG_MSG("lcore %u\n", lcore_id);
    }*/

}

int main (int argc, char *argv []) {

    if (argc != 3) {
        fprintf(stderr, "Usage: %s [config file] [host id]\n", argv[0]);
        exit(-1);
    }

    conf = Config_Init(argv[1]);
    uint32_t id = (uint32_t)strtoul(argv[2], NULL, 10);

    char* dpdk_args = conf_host_dpdk_args(conf);
    init_dpdk(dpdk_args);
    //DEBUG
    LOG_MSG("DPDK init sucessfully\n");
    uint32_t MAX_FLOW = conf_host_max_key(conf);
    uint32_t key_len = conf_common_key_len(conf);
    uint32_t interval_len = conf_common_interval_len(conf);
    const char* zmq_server = conf_common_zmq_data_server(conf);

    const char* dir = conf_common_trace_dir(conf);
    const char* filename = conf_common_pcap_list(conf);
    adapter_t* adapter = adapter_init(dir, filename);
    LOG_MSG("Trace file parse sucessfully\n");
    char tmp[100];
    sprintf(tmp, "%s/true_flows", dir);
    mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    ring = create_ringbuffer_shm("ring", sizeof(msg_t));
    host_ring = create_ringbuffer_shm("host_ring", sizeof(host_msg_t));

    version_start = (uint64_t*)calloc(max_version, sizeof(uint64_t));
    version_recv = (uint64_t*)calloc(max_version, sizeof(uint64_t));
    index1 = (uint32_t*)calloc(MAX_HOST_INDEX, sizeof(uint32_t));
    index2 = (uint32_t*)calloc(MAX_HOST_INDEX, sizeof(uint32_t));
    used = (uint32_t*)calloc(MAX_HOST_INDEX, sizeof(uint32_t));
    char* output_dir = NULL;
    sprintf(tmp, "../output/hosts/");
    output_dir = tmp;
    mkdir(output_dir,S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
    host_t* host = host_init(id, MAX_FLOW, key_len/8, interval_len, output_dir, zmq_server);

    pthread_attr_t attr;
    int s = pthread_attr_init(&attr);
    if (s != 0) {
        LOG_ERR("pthread_attr_init: %s\n", strerror(errno));
    }
    sem_init(&sem, 1, 0);
    s = pthread_create(&thread, &attr, io_thread, host);
    sem_wait(&sem);
    LOG_MSG("Controller_host IO thread init sucessfully\n");
    pthread_attr_t host_attr;
    s = pthread_attr_init(&host_attr);
    if(s != 0){
    LOG_ERR("host pthread attr init fail\n");
    }
    sem_init(&sem,1,0);
    s = pthread_create(&host_thread, &host_attr, host_io_thread, host);
    sem_wait(&sem);
    if (s != 0)
        LOG_ERR("pthread_create: %s\n", strerror(errno));
    else 
        LOG_MSG("Inter_host IO thread init sucessfully\n");


    tuple_t t;
    memset(&t, 0, sizeof(struct Tuple));
    memset(&send_msg, 0, sizeof(msg_t));
    send_msg.host_id = id;

    host_reset(host);
    //SJB **
    enum PACKET_STATUS temp_status;
    struct pcap_pkthdr pcap_h;
    const u_char *pkt = NULL;
    int pkt_len;
    while (1) {
        pkt = adapter_next(adapter, &t, &temp_status, &pcap_h);
        if (pkt == NULL) {
            break;
        }
        pkt_len = pcap_h.caplen < MAX_CAPLEN ? pcap_h.caplen : MAX_CAPLEN;
        host_process_packet(host, &t, pkt,pkt_len);
    }
    host_print(host, host->last_version);
    LOG_MSG("Send notify_end message to controller\n");
    send_msg.type = MSG_END;
    zmq_host_send(host->channel, &send_msg);
    while (write_ringbuffer(ring, &send_msg, sizeof(msg_t)) < 0) {}
    flush_ringbuffer(ring);
    host_send_msg.type = MSG_END;
    while (write_ringbuffer(host_ring, &host_send_msg,sizeof(host_msg_t)) < 0) {}
    flush_ringbuffer(host_ring);    
    
    LOG_MSG("Wait for IO thread finish\n");
    pthread_join(thread, NULL);
    pthread_join(host_thread, NULL); 

    adapter_destroy(adapter);
    host_destroy(host);

    for (uint32_t i=0; i<max_version; i++) {
        if (version_start[i] > 0) {
            LOG_MSG("%u %lu %lu %lu\n", i, version_start[i], version_recv[i], version_recv[i]-version_start[i]);
        }
    }

    free(version_start);
    free(version_recv);
    free(index1);
    free(index2);
    free(used);
    close_ringbuffer_shm(ring);
    close_ringbuffer_shm(host_ring);
    sleep(15);
    LOG_MSG("Execute sucessfully\n");
    return 0;
}
