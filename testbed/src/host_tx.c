#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>

#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>


#include <mtcp_api.h>
#include <mtcp_epoll.h>

#include "include/util.h"
#include "include/packet_helper.h"
#include "include/config.h"

#include <semaphore.h>

#include "host.h"
#include "include/adapter_pcap_ram.h"
#include "include/hash.h"

#define NB_MBUF   65536

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256


extern conf_t* conf;
sem_t sem;
pthread_mutex_t  mutex;
msg_t send_msg;
msg_t recv_msg;

uint32_t* switch_index1 = NULL;
uint32_t* switch_index2 = NULL;
uint32_t* index_in_use = NULL;
uint32_t n_index = 0;
uint32_t index_ptr = 0;

uint64_t* epoch_start = NULL;
uint64_t* epoch_recv = NULL;
uint32_t max_epoch = 1024;

struct rte_ring* send_ring = NULL;
struct rte_ring* recv_ring = NULL;
struct rte_mempool * om_pktmbuf_pool = NULL;

int DONE = FALSE;

void signal_handler(int signum) {
    DONE = TRUE;
}

uint32_t SEND = 0;
uint32_t PUT_RING = 0;

static int io_thread(void *arg) {
    LOG_MSG("Launch the dpdk io thread.\n");
	mtcp_core_affinitize(1);
    struct rte_mbuf  *mbuf;
    int ret;
    int nb_rx;
    int port_id = 1; // default dpdk1
    int queue_id = 0; 
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    while (1) {
        // send packets
        if (rte_ring_sc_dequeue(send_ring, (void**)&mbuf) == 0) {
            /* Add packet to the TX list. */
            rte_prefetch0(rte_pktmbuf_mtod(mbuf, void *));
            /* transmit */
            ret = rte_eth_tx_burst(port_id, queue_id, &mbuf, 1); 
            SEND += ret;
        }
        if (DONE) {
            if (SEND == PUT_RING) break;
        }
    }
}



uint32_t allocate_new_flow_2choice(tuple_t* t, uint32_t* r_index1, uint32_t* r_index2) {
    uint64_t key = now_us();
    uint32_t r1 = (uint32_t )MurmurHash64A(&key, sizeof(uint64_t), 3) % n_index;
    key = now_us();
    uint32_t r2 = (uint32_t )MurmurHash64A(&key, sizeof(uint64_t), 3) % n_index;

    uint32_t r = r1;
    if (index_in_use[r1] > index_in_use[r2]) {
        r = r2;
    }
    index_in_use[r]++;
    *r_index1 = switch_index1[r];
    *r_index2 = switch_index2[r];
    return r;
}

flow_metric_t* host_process_packet(host_t* host, tuple_t* t) {
    void* data = NULL;
    flow_metric_t* ret_data = NULL;

    uint32_t epoch = (uint32_t)(t->pkt_ts*1000/host->interval_len);
    if (unlikely(host->start_epoch == 0)) {
        host->start_epoch = epoch;
    }
    epoch = epoch - host->start_epoch;

    uint32_t local_epoch;
    pthread_mutex_lock(&mutex);
    if (unlikely(epoch > host->last_epoch)) {
        // LOG_MSG("pcap epoch %d in host process local epoch: %d\n", epoch, host->last_epoch);
        local_epoch = host->last_epoch;
        host->last_epoch = epoch;
        // Epoch updates in hybrid consistency
        //  On_New_Epoch_Local_Clock
        host_egress_print(host, local_epoch);
        msg_encode_sync(epoch, &send_msg);
        LOG_MSG("Local epoch %d update. Notify the controller\n", epoch);
        mtcp_host_send(host->mtcp_channel, &send_msg, host->mtcp_channel->sockid);
        host_reset(host);
        sleep(1);
    }
    pthread_mutex_unlock(&mutex); 

    host->interval_cnt++;
    int ret = rte_hash_lookup_data(host->egress_hash_table, t, &data);
    if (ret >= 0) {
        ret_data = (flow_metric_t*)data;
        if (t->fin_rst_flag) {
            index_in_use[ret_data->used_index]--;
        }
        if (epoch == ret_data->epoch) {
            ret_data->pkt_cnt += 1;
            ret_data->byte_cnt += t->byte;
        }
        else {
            ret_data->pkt_cnt = 1;
            ret_data->byte_cnt = t->byte;
            ret_data->epoch = epoch;
        }
    }
    else if (ret == -ENOENT) {
        if (host->cur_n >= host->max_n) {
            LOG_WARN("Reach max flow\n");
            return NULL;
        }
        ret_data = host->egress_flow_data+host->cur_n;
        ret_data->pkt_cnt = 1;
        ret_data->byte_cnt = t->byte;
        ret_data->epoch = epoch;
        ret_data->used_index = allocate_new_flow_2choice(t, &ret_data->switch_index1, &ret_data->switch_index2);
        ret = rte_hash_add_key_data(host->egress_hash_table, t, ret_data);
        if (ret != 0) {
            LOG_MSG("RTE Hash add error\n");
        }
        int32_t host_index;
        ret = rte_hash_lookup_bulk(host->egress_hash_table, (const void**)&t, 1, &host_index);
        if (ret != 0) {
            LOG_MSG("RTE lookup position error\n");
        }
        ret_data->host_index = host_index;
        host->cur_n += 1;
    }
    else {
        LOG_MSG("Lookup fail %d\n", ret);
    }

    return ret_data;
}

static inline void register_host_to_controller(host_t* host, int sockid) {
    struct mtcp_epoll_event ev;
    send_msg.host_id = host->id;
    send_msg.type = MSG_NEW_FLOW;
    mtcp_host_send(host->mtcp_channel, &send_msg, sockid);
    LOG_MSG("Register new host with id %d \n", host->id);

    ev.events = MTCP_EPOLLIN;
    ev.data.sockid = sockid;
    mtcp_epoll_ctl(host->mtcp_channel->mtcp_ctx, host->mtcp_channel->ep, 
        MTCP_EPOLL_CTL_MOD, host->mtcp_channel->sockid, &ev);
}

static inline void recv_switch_index_range(host_t* host, int sockid) {
    struct mtcp_epoll_event ev;
    large_msg_t large_recv_msg;
    mtcp_host_recv_large(host->mtcp_channel, &large_recv_msg, sockid);
    n_index = MAX_HOST_INDEX;
    msg_decode_new_flow_res(switch_index1, switch_index2, &n_index, &large_recv_msg);
    LOG_MSG("Received the switch index range from Controller.\n");
    LOG_MSG("Wait Controller notify start.\n");
}
                    
static inline int wait_notify_start(host_t* host, int sockid) {
    mtcp_host_recv(host->mtcp_channel, &recv_msg, sockid);
    if (strncmp(recv_msg.data, "start", 5) == 0) {
        LOG_MSG("Receive Controller notify_start_msg: %s.\n", recv_msg.data);
        return TRUE;
    }
    return FALSE;
}

static inline void handel_controller_msgs(host_t* host, int sockid, int* is_end) {
    mtcp_host_recv(host->mtcp_channel, &recv_msg, sockid);
    uint32_t epoch;
    uint32_t local_epoch;
    switch (recv_msg.type) {
        case MSG_SYNC:
            msg_decode_sync(&epoch, &recv_msg);
            LOG_MSG("Receive controller broadcast sync msg, epoch: %d.\n", epoch);
            if (epoch < max_epoch) {
                epoch_recv[epoch] = now_us();
            }
            // Epoch updates in hybrid consistency
            // On_New_Epoch_From_Controller
            pthread_mutex_lock(&mutex);
            if (host->last_epoch < epoch) {
                host->last_epoch = epoch;
                LOG_DEBUG("update local epoch %d from controller sync.\n", host->last_epoch);
            }
            pthread_mutex_unlock(&mutex);
            break;
        case MSG_NEW_FLOW:
            break;
        case MSG_END:
            *is_end = TRUE;
            break;
        default:
            LOG_WARN("should not be here\n");
            break;
    } 
}

void * host_mtcp_thread(void *arg) {

    LOG_MSG("Launch the host mtcp thread.\n");
    host_t* host = (host_t*)arg;

    LOG_MSG("Set core affinitize.\n");
	mtcp_core_affinitize(host->process_cpu);

    host_mtcp_connect(host);

    struct mtcp_epoll_event* events = (struct mtcp_epoll_event *)
			calloc(host->max_events, sizeof(struct mtcp_epoll_event));
	if (events == NULL) {
		LOG_ERR("Failed to allocate events!\n");
	}

    struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLOUT;
	ev.data.sockid = host->mtcp_channel->sockid;
	mtcp_epoll_ctl(host->mtcp_channel->mtcp_ctx, host->mtcp_channel->ep, 
        MTCP_EPOLL_CTL_ADD, host->mtcp_channel->sockid, &ev);


    int nevents;
    int init_flag = TRUE;
    int wait_flag = FALSE;
    int is_end = FALSE;
	while (1) {
		nevents = mtcp_epoll_wait(host->mtcp_channel->mtcp_ctx, host->mtcp_channel->ep, 
            events, host->max_events, -1);
		if (nevents < 0) {
			if (errno != EINTR) {
				LOG_ERR("mtcp_epoll_wait failed! ret: %d\n", nevents);
			}
			break;
		}
		for (int i = 0; i < nevents; i++) {
			if (events[i].events & MTCP_EPOLLERR) {
                host_mtcp_close(host);
				LOG_ERR("[CPU %d] Error on socket %d\n", 
						host->process_cpu, events[i].data.sockid);
			} else if (events[i].events & MTCP_EPOLLIN) {
                if (unlikely(init_flag)) {
                    recv_switch_index_range(host, events[i].data.sockid);
                    init_flag = FALSE;
                } else {                
                    if (unlikely(!wait_flag)) {
                        // wait controller to notify start
                        wait_flag = wait_notify_start(host, events[i].data.sockid);
                        if (wait_flag) {
                            LOG_MSG("All the hosts registered. System all green!\n");
                            sem_post(&sem);
                        }
                    } else {
                        handel_controller_msgs(host, events[i].data.sockid, &is_end);
                    }
                }
            } else if (events[i].events == MTCP_EPOLLOUT) {
                register_host_to_controller(host, events[i].data.sockid);  // the ack message 
			} else {
				LOG_ERR("Socket %d: event: %s\n", 
						events[i].data.sockid, EventToString(events[i].events));
				assert(0);
			}
		}
        if (DONE) {
            break;
        }
        if (is_end) {
            DONE = TRUE;
            break;
        }
    }

}


int main (int argc, char *argv []) {

    if (argc != 3) {
        fprintf(stderr, "Usage: %s [config file] [host id]\n", argv[0]);
        exit(-1);
    }

    conf = Config_Init(argv[1]);
    uint32_t id = (uint32_t)strtoul(argv[2], NULL, 10);


    // initialize mtcp env
    const char* project_path = conf_common_project_path(conf);

    char tmp[100];
    sprintf(tmp, "%s/config/mtcp_om_host.conf", project_path);
    // const char* mtcp_conf_file = conf_host_mtcp_conf_file(conf);
    uint32_t process_cpu = conf_host_process_cpu(conf);
    struct mtcp_conf mcfg;
    /** 
     * it is important that core limit is set before mtcp_init() is called. 
     * You cannot set core_limit after mtcp_init()
     */
    mtcp_getconf(&mcfg);
    mcfg.num_cores = 2;  // mtcp app thread num, affect the queue num of nic
    mtcp_setconf(&mcfg);

    LOG_MSG("Initialize the mtcp env.\n");
    int ret = mtcp_init(tmp);
	if (ret) {
		LOG_ERR("Failed to initialize mtcp.\n");
	}

    // init dpdk ring
    LOG_MSG("Initialize the dpdk ring.\n");
    send_ring = rte_ring_create("send_ring", NB_MBUF, SOCKET_ID_ANY, 
        RING_F_SP_ENQ | RING_F_SC_DEQ);
    recv_ring = rte_ring_create("recv_ring", NB_MBUF, SOCKET_ID_ANY, 
        RING_F_SP_ENQ | RING_F_SC_DEQ);

    /* create the mbuf pool */
    LOG_MSG("Create the mbuf pool.\n");
	om_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (om_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	int nb_ports = rte_eth_dev_count();
    LOG_MSG("check the dpdk NIC count: %d.\n", nb_ports);
	if (nb_ports < 2)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    // trace
    const char* dir = conf_common_trace_dir(conf);
    if (strlen(dir) == 0) {
        // use the provided trace
        sprintf(tmp, "%s/trace/", project_path);
        dir = tmp;
    }
    const char* pcap_list = conf_common_pcap_list(conf);
    adapter_t* adapter = adapter_init(dir, pcap_list);


    uint32_t key_len = conf_common_key_len(conf);
    uint32_t interval_len = conf_common_interval_len(conf);

    const char* controller_ip = conf_controller_ip_addr(conf);
    uint32_t listen_port = conf_controller_listen_port(conf);

    uint32_t max_events = conf_host_max_events(conf);
    uint32_t MAX_FLOW = conf_host_max_key(conf);


    epoch_start = (uint64_t*)rte_zmalloc("epoch_start", max_epoch * sizeof(uint64_t), RTE_CACHE_LINE_SIZE);
    if (epoch_start == NULL) {
        LOG_ERR("RTE allocate error\n");
    }
    epoch_recv = (uint64_t*)rte_zmalloc("epoch_recv", max_epoch * sizeof(uint64_t), RTE_CACHE_LINE_SIZE);
    if (epoch_recv == NULL) {
        LOG_ERR("RTE allocate error\n");
    }
    switch_index1 = (uint32_t*)rte_zmalloc("switch_index1", MAX_HOST_INDEX * sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
    if (switch_index1 == NULL) {
        LOG_ERR("RTE allocate error\n");
    }
    switch_index2 = (uint32_t*)rte_zmalloc("switch_index2", MAX_HOST_INDEX * sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
    if (switch_index2 == NULL) {
        LOG_ERR("RTE allocate error\n");
    }
    index_in_use = (uint32_t*)rte_zmalloc("index_in_use", MAX_HOST_INDEX * sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
    if (index_in_use == NULL) {
        LOG_ERR("RTE allocate error\n");
    }

    // host init
    sprintf(tmp, "%s/output/", project_path);
    char* output_dir = tmp;
    mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    host_t* host = host_init(id, MAX_FLOW, key_len/8, interval_len, output_dir, 
        process_cpu, controller_ip, listen_port, max_events);

    pthread_mutex_init(&mutex, NULL);
    sem_init(&sem, 0, 0);
    static pthread_t h_thread;
    pthread_create(&h_thread, NULL, host_mtcp_thread, (void *)host);
    sem_wait(&sem);
    static pthread_t io_t, recv_t;
    pthread_create(&io_t, NULL, io_thread, NULL);

    LOG_DEBUG("Main Thread: Start to process the pcap trace.\n");
    tuple_t t;
    memset(&t, 0, sizeof(struct Tuple));
    memset(&send_msg, 0, sizeof(msg_t));
    send_msg.host_id = id;

	mtcp_core_affinitize(3);

    host_reset(host);
    const u_char* raw_pkt;
    struct pcap_pkthdr hdr;
    uint8_t extend_pkt[MAX_CAPLEN];
    om_header_t om_header;
    uint32_t pkt_len;
    while (1) {
        enum PACKET_STATUS status;
        raw_pkt = adapter_next_pkt(adapter, &t, &status, &hdr);
        if (raw_pkt == NULL) {
            break;
        }

        if (status != STATUS_VALID) {
            continue;
        }
        flow_metric_t* fm = host_process_packet(host, &t);

        om_header.epoch = fm->epoch % 256;
        om_header.host_index = htonl(fm->host_index);
        om_header.switch_index1 = htons(fm->switch_index1);
        om_header.switch_index2 = htons(fm->switch_index2);

        pkt_len = hdr.caplen < MAX_CAPLEN ? hdr.caplen : MAX_CAPLEN;
        memset(extend_pkt, 0, MAX_CAPLEN);
        memcpy(extend_pkt, raw_pkt, sizeof(struct ether_hdr));
        memcpy(extend_pkt + sizeof(struct ether_hdr), &om_header, sizeof(om_header_t));
        memcpy(extend_pkt + sizeof(struct ether_hdr) + sizeof(om_header_t), raw_pkt + sizeof(struct ether_hdr), pkt_len - sizeof(struct ether_hdr));
        hdr.caplen += sizeof(om_header_t);
        hdr.len += sizeof(om_header_t);

        /* allocate rte_mbuf */
        struct rte_mbuf* m = rte_pktmbuf_alloc(om_pktmbuf_pool);
        if (unlikely(m == NULL)) {
            printf("allocate mbuf failed.\n");
            return -1;
        }
        rte_memcpy((uint8_t *)((uint8_t *)m->buf_addr + m->data_off), (uint8_t *)extend_pkt, hdr.caplen);
        m->pkt_len  = hdr.caplen;
        m->data_len = hdr.caplen;
        while (rte_ring_sp_enqueue(send_ring, m) != 0) {}
        PUT_RING ++;
    }

    send_msg.type = MSG_END;
    mtcp_host_send(host->mtcp_channel, &send_msg, host->mtcp_channel->sockid);

    LOG_DEBUG("SEND-packets: %d\n", SEND);
    LOG_DEBUG("PUT RING-packets: %d\n", PUT_RING);

    pthread_join(io_t, NULL);
    pthread_join(h_thread, NULL);

    adapter_destroy(adapter);
    host_destroy(host);
    sem_destroy(&sem);

    rte_free(epoch_start);
    rte_free(epoch_recv);
    rte_free(switch_index1);
    rte_free(switch_index2);
    rte_free(index_in_use);
    rte_ring_free(send_ring);
    rte_ring_free(recv_ring);

    return 0;
}

