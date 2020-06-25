//
// Created by qhuang on 12/8/18.
//

#ifndef __OMNIMON_HOST_H__
#define __OMNIMON_HOST_H__

#include <stdint.h>
#include <stdio.h>
#include <stdatomic.h>

#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "include/config.h"
#include "include/packet_helper.h"
#include "include/util.h"
#include "packet.h"
#include "channel.h"



typedef struct omnimon_header_t {
    uint32_t host_index;
    uint8_t  epoch;
    uint16_t switch_index1;
    uint16_t switch_index2;
} om_header_t;

typedef struct FlowMetric {
    uint32_t pkt_cnt;
    uint32_t byte_cnt;

    uint32_t switch_index1;
    uint32_t switch_index2;
    uint32_t epoch;
    int32_t  host_index;

    uint32_t used_index;
    double start_ts;
    double end_ts;
    int start_epoch;
    int end_epoch;
} flow_metric_t;

typedef struct IngressFlowMetric {
    uint32_t pkt_cnt;
    uint32_t byte_cnt;
} ingress_flow_metric_t;




typedef struct Host {
    uint32_t id;
    uint32_t max_n;
    uint32_t interval_len;
    const char* output_dir;
    uint32_t cur_n;
    uint32_t start_epoch;
    uint32_t last_epoch;
    uint64_t interval_cnt;
    uint64_t start_ts;
    struct rte_hash* egress_hash_table;
    flow_metric_t* egress_flow_data;
    uint32_t output_epoch;
    uint32_t process_cpu;
    const char* controller_ip;
    uint32_t listen_port;
    uint32_t max_events;
    mtcp_host_channel_t* mtcp_channel;
} host_t;

host_t* host_init(uint32_t id, uint32_t n, uint32_t key_byte, uint32_t interval_len,
        const char* output_dir, uint32_t core, const char* ip, uint32_t port,
        uint32_t max_events);
void host_destroy(host_t* host);
void host_print(host_t* host, int cur_interval);
void host_reset(host_t* host);

void host_connect(host_t* host, const char* zmq_server);

host_t* host_init(uint32_t id, uint32_t n, uint32_t key_byte, uint32_t interval_len,
        const char* output_dir, uint32_t core, const char* ip, uint32_t port,
        uint32_t max_events) {
    host_t* ret = rte_zmalloc(NULL, sizeof(host_t), RTE_CACHE_LINE_SIZE);
    ret->id = id;
    ret->max_n = n;
    ret->interval_len = interval_len;
    ret->output_dir = output_dir;
    ret->process_cpu = core;
    ret->controller_ip = ip;
    ret->listen_port = port;
    ret->max_events = max_events;
    ret->start_epoch = 0;
    ret->last_epoch = 0;


    ret->egress_flow_data = (flow_metric_t*)rte_zmalloc("eg_flowmetric", 
        n*sizeof(flow_metric_t), RTE_CACHE_LINE_SIZE);
    if (ret->egress_flow_data == NULL) {
        LOG_ERR("RTE allocate error\n");
    }
    for (int i=0; i<n; i++) {
        ret->egress_flow_data[i].pkt_cnt = 1;
        ret->egress_flow_data[i].byte_cnt = 0;
    }


    struct rte_hash_parameters params;
    bzero(&params, sizeof(struct rte_hash_parameters));
    char tmp[25];
    sprintf(tmp, "host_%d_egress", id);
    params.name = tmp;
    params.entries = n;
    params.reserved = 0;
    params.key_len = key_byte;
    params.hash_func = rte_jhash;
    params.hash_func_init_val = 0;
    ret->egress_hash_table = rte_hash_create(&params);
    if (ret->egress_hash_table == NULL) {
        LOG_MSG("rte hash create error\n");
    }

    ret->output_epoch = 0;
    return ret;
}


void host_mtcp_connect(host_t* host) {
    host->mtcp_channel = mtcp_host_channel_init(host->controller_ip, host->listen_port, 
        host->max_events, host->process_cpu);
}

void host_mtcp_close(host_t* host) {
    mtcp_epoll_ctl(host->mtcp_channel->mtcp_ctx, host->mtcp_channel->ep, 
        MTCP_EPOLL_CTL_DEL, host->mtcp_channel->sockid, NULL);
	mtcp_close(host->mtcp_channel->mtcp_ctx, host->mtcp_channel->sockid);
}

void host_destroy(host_t* host) {
    rte_hash_free(host->egress_hash_table);

    rte_free(host->egress_flow_data);
    rte_free(host);
}

void host_ingress_print(host_t* host, ingress_flow_metric_t** ingress_flow_datas) {

    char tmp[100];
    sprintf(tmp, "%s/epoch_%d/", host->output_dir, host->output_epoch);
    mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    sprintf(tmp, "%s/epoch_%d/dst1_%u.txt", host->output_dir, host->output_epoch, host->id);

    FILE* output_file = fopen(tmp, "w");
    if (output_file == NULL) {
        LOG_ERR("open file failed!\n");
    }
    int within = host->output_epoch % 4;
    ingress_flow_metric_t* igfm = ingress_flow_datas[within];
    uint32_t total_pkt = 0;
    for (int i = 0; i < host->max_n; i++) {
        if (igfm[i].pkt_cnt > 0) {
            fprintf(output_file, "%u %u\n", i, igfm[i].pkt_cnt);
            total_pkt += igfm[i].pkt_cnt;
        }
    }
    LOG_DEBUG("OUTPUT, epoch %d pkts: %d.\n", host->output_epoch, total_pkt);
    host->output_epoch += 1;
    fclose(output_file);
    memset((void *)ingress_flow_datas[within], 0, sizeof(ingress_flow_metric_t)*host->max_n);
}


void host_egress_print(host_t* host, int epoch) {
    char tmp[100];
    char tmp2[100];
    sprintf(tmp, "%s/epoch_%d/", host->output_dir, epoch);
    mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    sprintf(tmp, "%s/epoch_%d/src%u.txt", host->output_dir, epoch, host->id);
    sprintf(tmp2, "%s/epoch_%d/path.txt", host->output_dir, epoch);

    FILE* output_file = fopen(tmp, "w");
    FILE* path_file = fopen(tmp2, "w");
    if (output_file == NULL || path_file == NULL) {
        LOG_ERR("open file failed!\n");
    }
    uint32_t next = 0;
    const void* key = NULL;
    void* data = NULL;
    int ret = 0;
    tuple_t t;
    uint32_t total_pkt = 0;

    while (1) {
        ret = rte_hash_iterate(host->egress_hash_table, &key, &data, &next);
        if (ret == -ENOENT) {
            break;
        }
        else if (ret == -EINVAL) {
            LOG_MSG("RTE Hash invalid parameter\n");
            break;
        }

        memcpy(&t, key, sizeof(flow_key_t));
        flow_metric_t* flow_data = (flow_metric_t*)data;
        fprintf(output_file, "%s(%u) <-> %s(%u) %u; %u\n",
                ip2a(t.key.src_ip, ip1), t.key.src_port,
                ip2a(t.key.dst_ip, ip2), t.key.dst_port,
                t.key.proto, flow_data->pkt_cnt
        );
        total_pkt += flow_data->pkt_cnt;
        // 10.0.0.1:10000 <-> 10.0.0.2:80 6; h2:8 s1:3,5 s3:3,5 h10:8
        fprintf(path_file, "%s(%u) <-> %s(%u) %u; h1:%u s1:%u,%u h2:%u\n",
                ip2a(t.key.src_ip, ip1), t.key.src_port,
                ip2a(t.key.dst_ip, ip2), t.key.dst_port,
                t.key.proto, flow_data->host_index, 
                flow_data->switch_index1, flow_data->switch_index2,
                flow_data->host_index
        );

    }

    fclose(output_file);
    fclose(path_file);
    
}

void host_reset(host_t* host) {
    rte_hash_reset(host->egress_hash_table);
    host->cur_n = 0;
    host->interval_cnt = 0;
    host->start_ts = now_us();
}


#endif //__OMNIMON_HOST_H__
