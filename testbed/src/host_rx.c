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
pthread_mutex_t  mutex;
sem_t sem;
msg_t send_msg;
msg_t recv_msg;

uint32_t* switch_index1 = NULL;
uint32_t* switch_index2 = NULL;
uint32_t n_index = 0;
uint32_t index_ptr = 0;

uint64_t* epoch_start = NULL;
uint64_t* epoch_recv = NULL;
uint32_t max_epoch = 1024;

struct rte_ring* recv_ring = NULL;
struct rte_mempool * om_pktmbuf_pool = NULL;

ingress_flow_metric_t** ingress_flow_data = NULL;


int DONE = FALSE;

void signal_handler(int signum) {
    DONE = TRUE;
    sem_post(&sem);
}

uint32_t recv_pkts = 0;
static int io_thread(void *arg) {
    LOG_MSG("Launch the dpdk io thread.\n");
	mtcp_core_affinitize(1);
    struct rte_mbuf  *mbuf;
    int ret;
    int nb_rx;
    int port_id = 1; // default dpdk1
    int queue_id = 1; 
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    while (1) {
        // receive packets
        for (int q = 0; q < 2; q++) {
            nb_rx = rte_eth_rx_burst(port_id, q,
                pkts_burst, MAX_PKT_BURST);
            recv_pkts += nb_rx;
            for(int i = 0; i < nb_rx; i++) {
                mbuf = pkts_burst[i];
                while(rte_ring_sp_enqueue(recv_ring, mbuf) != 0) {}
            }
        }

        if (DONE) {
            sem_post(&sem);
            break;
        }
    }
}

static void decode_omnimon_pkts(const char* pkt, tuple_t* t) {
    struct ip* ip_hdr = (struct ip*)(pkt + sizeof(om_header_t) + sizeof(struct ether_hdr));
    t->key.src_ip = ip_hdr->ip_src.s_addr;
    t->key.dst_ip = ip_hdr->ip_dst.s_addr;
    t->key.proto = ip_hdr->ip_p;
    t->byte = ntohs(ip_hdr->ip_len);
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp_hdr = (struct tcphdr*)((uint8_t*)ip_hdr + (ip_hdr->ip_hl << 2));
        t->key.src_port = ntohs(tcp_hdr->source);
        t->key.dst_port = ntohs(tcp_hdr->dest);
    }
    else if (ip_hdr->ip_p == IPPROTO_UDP) {
        struct udphdr* udp_hdr = (struct udphdr*)((uint8_t*)ip_hdr + (ip_hdr->ip_hl << 2));
        t->key.src_port = ntohs(udp_hdr->source);
        t->key.dst_port = ntohs(udp_hdr->dest);
    }
}


static void host_recv_thread(void *arg) {

    LOG_MSG("Launch the host recv thread.\n");
    host_t* host = (host_t*)arg;
	mtcp_core_affinitize(2);
    struct rte_mbuf  *mbuf;
    int ret;
    void* data = NULL;
    ingress_flow_metric_t* ig_data = NULL;
    uint8_t epoch;
    uint8_t within;
    uint32_t host_index;
    tuple_t t;
    memset(&t, 0, sizeof(struct Tuple));

    uint32_t tmp_index = 0;
    while (1) {
        if (rte_ring_sc_dequeue(recv_ring, (void**)&mbuf) == 0) {
            /* Add packet to the TX list. */
            rte_prefetch0(rte_pktmbuf_mtod(mbuf, void *));
            struct ether_hdr *pkt = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
            decode_omnimon_pkts((const char*)pkt, &t);
            // hybrid sync protocol 
            om_header_t* om = (om_header_t *)(((const u_char*)pkt) + sizeof(struct ether_hdr));
            epoch = om->epoch;
            pthread_mutex_lock(&mutex);
            if (unlikely(epoch > host->last_epoch)) {
                LOG_DEBUG("receive the embed new epoch: %d.\n", epoch);
                host->last_epoch = epoch;
                if (epoch - host->output_epoch > 1) {
                    sem_post(&sem);
                }
            }
            pthread_mutex_unlock(&mutex);

            // value update of ingress table
            within = epoch % 4;
            host_index = ntohl(om->host_index);

            ig_data = ingress_flow_data[within] + host_index;
            if (ig_data->pkt_cnt == 0) {
                ig_data->pkt_cnt = 1;
                ig_data->byte_cnt = t.byte;
            } else {
                ig_data->pkt_cnt += 1;
                ig_data->byte_cnt += t.byte;
            }
        }
        if (DONE) {
            break;
        }
    }
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
    // LOG_MSG("recv switch index.\n");
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
                LOG_MSG("Move into epoch %d by controller sync.\n", host->last_epoch);
                if (epoch - host->output_epoch > 1) {
                    sem_post(&sem);
                }
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
            sleep(3);
            DONE=TRUE;
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
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    uint32_t key_len = conf_common_key_len(conf);
    uint32_t interval_len = conf_common_interval_len(conf);

    const char* controller_ip = conf_controller_ip_addr(conf);
    uint32_t listen_port = conf_controller_listen_port(conf);

    uint32_t max_events = conf_host_max_events(conf);
    uint32_t MAX_FLOW = conf_host_max_key(conf);


    epoch_start = (uint64_t*)rte_zmalloc(NULL, max_epoch * sizeof(uint64_t), RTE_CACHE_LINE_SIZE);
    if (epoch_start == NULL) {
        LOG_ERR("RTE allocate error\n");
    }
    epoch_recv = (uint64_t*)rte_zmalloc(NULL, max_epoch * sizeof(uint64_t), RTE_CACHE_LINE_SIZE);
    if (epoch_recv == NULL) {
        LOG_ERR("RTE allocate error\n");
    }
    switch_index1 = (uint32_t*)rte_zmalloc(NULL, MAX_HOST_INDEX * sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
    if (switch_index1 == NULL) {
        LOG_ERR("RTE allocate error\n");
    }
    switch_index2 = (uint32_t*)rte_zmalloc(NULL, MAX_HOST_INDEX * sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
    if (switch_index2 == NULL) {
        LOG_ERR("RTE allocate error\n");
    }

    ingress_flow_data = (ingress_flow_metric_t**)rte_zmalloc("ig_flowmetrics", 
        4*sizeof(ingress_flow_metric_t*), RTE_CACHE_LINE_SIZE);
    ingress_flow_data[0] = (ingress_flow_metric_t*)rte_zmalloc("ig_flowmetric",
        4*MAX_FLOW*sizeof(ingress_flow_metric_t), RTE_CACHE_LINE_SIZE);
    if (ingress_flow_data == NULL || ingress_flow_data[0] == NULL) {
        LOG_ERR(" allocate error\n");
    }

    for (int i = 0; i < 4; i++) {
        ingress_flow_data[i] = (ingress_flow_metric_t*)(ingress_flow_data[0] + (i * MAX_FLOW));
    }
    // host init

    sprintf(tmp, "%s/output/", project_path);
    char* output_dir = tmp;
    mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    host_t* host = host_init(id, MAX_FLOW, key_len/8, interval_len, output_dir, 
        process_cpu, controller_ip, listen_port, max_events);

    // sem_init(&sem, 1, 0);
    sem_init(&sem, 0, 0);
    pthread_mutex_init(&mutex, NULL);
    static pthread_t h_thread;
    static pthread_t io_t, recv_t;
    pthread_create(&h_thread, NULL, host_mtcp_thread, (void *)host);
    pthread_create(&io_t, NULL, io_thread, NULL);
    pthread_create(&recv_t, NULL, host_recv_thread, (void *)host);
    sem_wait(&sem);

    LOG_DEBUG("Main Thread: Start to process the pcap trace.\n");
    tuple_t t;
    memset(&t, 0, sizeof(struct Tuple));
    memset(&send_msg, 0, sizeof(msg_t));
    send_msg.host_id = id;

	mtcp_core_affinitize(3);

    host_reset(host);
    const u_char* raw_pkt;
    struct pcap_pkthdr hdr;
    uint8_t extend_pkt[1509];
    om_header_t om_header;
    uint32_t pkt_len;
    while (1) {
        sem_wait(&sem);
        if (DONE) {
            break;
        }
        host_ingress_print(host, ingress_flow_data);
    }
    sleep(1);
    while (host->output_epoch < host->last_epoch)
        host_ingress_print(host, ingress_flow_data); // , ingress_flow_key);

    struct rte_eth_stats eth_stats;
    rte_eth_stats_get(1, &eth_stats);
    LOG_DEBUG("Total number of successfully received packets %d.\n", eth_stats.ipackets);
    LOG_DEBUG("Total of RX packets dropped by the HW, because there are no available buffer (i.e. RX queues are full). %d.\n", eth_stats.imissed);
    LOG_DEBUG("Total number of erroneous received packets %d\n", eth_stats.ierrors);
    LOG_DEBUG("Receive packets: %d.\n", recv_pkts);

    host_destroy(host);

    rte_free(epoch_start);
    rte_free(epoch_recv);
    rte_free(switch_index1);
    rte_free(switch_index2);
    rte_free(ingress_flow_data[0]);
    rte_free(ingress_flow_data);
    rte_ring_free(recv_ring);

    return 0;
}
