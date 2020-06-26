//
// Created by qhuang on 12/8/18.
//

#ifndef ULTRAMON_HOST_H
#define ULTRAMON_HOST_H

#include <stdint.h>
#include <stdio.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "include/config.h"
#include "include/packet_helper.h"
#include "include/util.h"
#include "packet.h"
#include "channel.h"


typedef struct FlowMetric {
    uint32_t pkt_cnt;
    uint32_t byte_cnt;

    uint32_t index1;
    uint32_t index2;
    uint32_t version;
    int32_t position;
    //SJB624
    uint8_t s1;
    uint8_t s2;
    uint8_t s3;
    uint8_t dst;
    //SJB
} flow_metric;

typedef struct IngressFlowMetric {
    uint32_t pkt_cnt;
    uint32_t byte_cnt;
    uint32_t epoch;
} ingress_flow_metric_t;

typedef struct Host {
    uint32_t id;
    uint32_t max_n;
    uint32_t interval_len;
    const char* output_dir;
    zmq_host_channel_t* channel;
    uint32_t cur_n;
    uint32_t start_version;
    uint32_t last_version;
    uint64_t interval_cnt;
    uint64_t start_ts;

    /****** chenxiang ******/
    // hashtable for receiver
    flow_key_t* ingress_flow_key;
    ingress_flow_metric_t* ingress_flow_data;
    /***********************/

    struct rte_hash* hash_table;
    flow_metric* flow_data;
} host_t;

host_t* host_init(uint32_t id, uint32_t n, uint32_t key_byte, uint32_t interval_len,
        const char* output_dir, const char* zmq_server);
void host_destroy(host_t* host);
void host_print(host_t* host, int cur_interval);
void host_reset(host_t* host);
//SJB **
flow_metric* host_process_packet(host_t* host, tuple_t* t, const u_char *pkt,int pkt_len);
pcap_t *pcap_init(char *err_buf);

pcap_t *pcap_init(char *err_buf){
    pcap_t *handle = NULL;
    char *dev = NULL;
    dev = pcap_lookupdev(err_buf);
    if(dev == NULL)
        printf("Error: can not find any device\n");
    handle = pcap_open_live(dev, BUFSIZ, 1, -1, err_buf);
    if (handle == NULL)
    printf("open device %s fail\n",dev);
    return handle;
}
//SJB

host_t* host_init(uint32_t id, uint32_t n, uint32_t key_byte, uint32_t interval_len,
        const char* output_dir, const char* zmq_server) {
    host_t* ret = rte_zmalloc(NULL, sizeof(host_t), RTE_CACHE_LINE_SIZE);
    ret->id = id;
    ret->max_n = n;
    ret->interval_len = interval_len;
    ret->output_dir = output_dir;

    char addr1[50], addr2[50];
    sprintf(addr1, "%s:%d", zmq_server, 9000);
    sprintf(addr2, "%s:%d", zmq_server, id+9000);
    ret->channel = zmq_host_channel_init(addr1, addr2);

    ret->flow_data = (flow_metric*)rte_zmalloc(NULL, n*sizeof(flow_metric), RTE_CACHE_LINE_SIZE);
    if (ret->flow_data == NULL) {
        LOG_ERR("RTE allocate error\n");
    }
    for (int i=0; i<n; i++) {
        ret->flow_data[i].pkt_cnt = 1;
        ret->flow_data[i].byte_cnt = 0;
    }

    struct rte_hash_parameters params;
    bzero(&params, sizeof(struct rte_hash_parameters));
    params.name = NULL;
    params.entries = n;
    params.reserved = 0;
    params.key_len = key_byte;
    params.hash_func = rte_jhash;
    params.hash_func_init_val = 0;
    // params.socket_id = 0;
    ret->hash_table = rte_hash_create(&params);
    if (ret->hash_table == NULL) {
        LOG_MSG("rte hash create error\n");
    }


    /****** chenxiang ******/
    uint32_t rte_hash_num_buckets = rte_align32pow2(n) / 8;
    ret->ingress_flow_data = (ingress_flow_metric_t*)rte_zmalloc("ig_flowmetric", 
        n*sizeof(ingress_flow_metric_t), RTE_CACHE_LINE_SIZE);
    if (ret->ingress_flow_data == NULL) {
        LOG_ERR("RTE allocate error\n");
    }
    ret->ingress_flow_key = (flow_key_t*)rte_zmalloc("ig_flowkey",
        n*sizeof(flow_key_t), RTE_CACHE_LINE_SIZE);
    if (ret->ingress_flow_key == NULL) {
        LOG_ERR("RTE allocate error\n");
    }
    /***********************/

    return ret;
}

void host_destroy(host_t* host) {
    rte_hash_free(host->hash_table);
    rte_free(host->flow_data);
    zmq_host_channel_free(host->channel);
    rte_free(host);
}

void host_print(host_t* host, int cur_interval) {
    uint64_t cur_ts = now_us();
    //LOG_MSG("%lf\n", 1.0*host->interval_cnt/(cur_ts-host->start_ts));
    if (host->output_dir == NULL) {
        return;
    }

    char tmp[100];
    char tmp1[100];
    sprintf(tmp, "%sthpt_%d.txt", host->output_dir, host->id);
    FILE* thpt_file = NULL;
    if (cur_interval > 0) {
        thpt_file = fopen(tmp, "a");
    }
    else {
        thpt_file = fopen(tmp, "w");
    }
    if (thpt_file == NULL) {
        LOG_ERR("fail to open file %s\n", tmp);
    }
    fprintf(thpt_file, "%lf\n", 1.0*host->interval_cnt/(cur_ts-host->start_ts));
    fclose(thpt_file);

    // tuple_t* tuple_ret = (tuple_t*)calloc(host->cur_n, sizeof(tuple_t));
    sprintf(tmp, "%shost%u_%d", host->output_dir, host->id, cur_interval);
    sprintf(tmp1, "%spath%u_%d", host->output_dir, host->id, cur_interval);
    FILE* output_file = fopen(tmp, "w");
    FILE* path_file = fopen(tmp1,"w");
    uint32_t next = 0;
    const void* key = NULL;
    void* data = NULL;
    int ret = 0;
    // size_t cnt = 0;
    tuple_t t;
    while (1) {
        ret = rte_hash_iterate(host->hash_table, &key, &data, &next);
        if (ret == -ENOENT) {
            break;
        }
        else if (ret == -EINVAL) {
            LOG_MSG("RTE Hash invalid parameter\n");
            break;
        }
	flow_metric* flow_data = (flow_metric *)data;
        memcpy(&t, key, sizeof(flow_key_t));
        fprintf(output_file, "%s:%u <-> %s:%u %u; %u\n",
                ip2a(t.key.src_ip, ip1), t.key.src_port,
                ip2a(t.key.dst_ip, ip2), t.key.dst_port,
                t.key.proto,flow_data->pkt_cnt
        );
         fprintf(path_file, "%s:%u <-> %s:%u %u; ",
                ip2a(t.key.src_ip, ip1), t.key.src_port,
                ip2a(t.key.dst_ip, ip2), t.key.dst_port,
                t.key.proto
        );
	fprintf(path_file,"h%u:%u ",host->id,flow_data->position);
	if(flow_data->s1 != 0)
	fprintf(path_file,"s%u:%u,%u ",flow_data->s1,flow_data->index1,flow_data->index2);
	if(flow_data->s2 != 0)
	fprintf(path_file,"s%u:%u,%u ",flow_data->s2,flow_data->index1,flow_data->index2);
	if(flow_data->s3 != 0)
	fprintf(path_file,"s%u:%u,%u ",flow_data->s3,flow_data->index1,flow_data->index2);
	fprintf(path_file,"h%u:%u\n",flow_data->dst,flow_data->position);        
// tuple_ret[cnt].byte = flow_data->byte_cnt;
        // cnt++;
    }

    // qsort (tuple_ret, cnt, sizeof(tuple_t), cmp);
    // for (int i=0; i<cnt; i++) {
    //    print_tuple(output_file, tuple_ret+i);
    // }
    fclose(output_file);
    fclose(path_file);
    // free(tuple_ret);
}


/****** chenxiang ******/
void host_ingress_print(host_t* host, int cur_interval) {
    char tmp[100];
    sprintf(tmp, "%sdst%u_%d", host->output_dir, host->id, cur_interval);
    FILE* output_file = fopen(tmp, "w");
    if (output_file == NULL) {
        LOG_ERR("open file failed!");
    }
    flow_key_t* t;
    for (int i = 0; i < host->max_n; i++) {
        if (host->ingress_flow_data[i].pkt_cnt > 0) {
            t = host->ingress_flow_key + i;
            fprintf(output_file, "%s(%u) <-> %s(%u) %u; %d: %u\n",
                ip2a(t->src_ip, ip1), t->src_port,
                ip2a(t->dst_ip, ip2), t->dst_port,
                t->proto, i, host->ingress_flow_data[i].pkt_cnt
            );
        }
    }
    fclose(output_file);
}
/***********************/


void host_reset(host_t* host) {
    rte_hash_reset(host->hash_table);
    host->cur_n = 0;
    host->interval_cnt = 0;
    host->start_ts = now_us();

    /****** chenxiang ******/
    memset(host->ingress_flow_data, 0, sizeof(ingress_flow_metric_t)*host->max_n);
    memset(host->ingress_flow_key, 0, sizeof(flow_key_t)*host->max_n);
    /***********************/
}


#endif //ULTRAMON_HOST_H
