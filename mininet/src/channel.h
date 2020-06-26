//
// Created by qhuang on 11/21/18.
//

#ifndef ULTRAMON_CHANNEL_H
#define ULTRAMON_CHANNEL_H

#include <zmq.h>
#include "packet.h"
#include "include/util.h"

enum MSG_T {MSG_NEW_FLOW, MSG_HOST_DATA, MSG_SYNC, MSG_END};
#define HOST_NUM 4
#define MAX_MSG_DATA 16
#define ARRAY_LENGTH 2048
#define INDEX_RANGE (ARRAY_LENGTH*ARRAY_LENGTH)
#define MAX_HOST_INDEX   (INDEX_RANGE / HOST_NUM)
#define MAX_LARGE_DATA (4*MAX_HOST_INDEX)
typedef struct __attribute__ ((__packed__)) Message {
    uint32_t host_id;
    enum MSG_T type;
    uint32_t size;
    unsigned char data[MAX_MSG_DATA];
} msg_t;

typedef struct __attribute__ ((__packed__)) LargeMessage {
    uint32_t host_id;
    enum MSG_T type;
    uint32_t size;
    unsigned char data[MAX_LARGE_DATA];
} large_msg_t;

//SJB **
#define MAX_HOST_DATA 256
typedef struct __attribute__ ((__packed__)) NormalMessage {
    uint32_t host_id;
    enum MSG_T type;
    uint32_t size;
    struct ominimon_header o_header;
    unsigned char data[MAX_HOST_DATA];
} host_msg_t;
//SJB

typedef struct ZMQHostChannel {
    void* zmq_ctx;
    void* to_socket;
    void* from_socket;
} zmq_host_channel_t;


typedef struct ZMQControllerChannel {
    void* zmq_ctx;
    void* listen_socket;
    uint32_t n_host;
    void** send_socket;
} zmq_controller_channel_t;

void zmq_controller_recv(zmq_controller_channel_t* channel, msg_t* msg);


zmq_host_channel_t* zmq_host_channel_init(char *addr1, char *addr2) {
    zmq_host_channel_t* ret = (zmq_host_channel_t*)calloc(1, sizeof(zmq_host_channel_t));
    if (ret == NULL) {
        LOG_ERR("zmq channel allocate error\n");
    }

    ret->zmq_ctx = zmq_ctx_new();
    if (ret->zmq_ctx == 0) {
        LOG_ERR("zmq_ctx_new(): %s\n", zmq_strerror(errno));
    }
    // if (zmq_ctx_set(ret->zmq_ctx, ZMQ_IO_THREADS, 1) == -1) {
    //     LOG_ERR("zmq_ctx_set(): %s\n", zmq_strerror(errno));
    // }

    ret->to_socket = zmq_socket(ret->zmq_ctx, ZMQ_PUSH);
    ret->from_socket = zmq_socket(ret->zmq_ctx, ZMQ_PULL);
    if (zmq_connect(ret->to_socket, addr1) == -1) {
        LOG_ERR("zmq_connect(): %s\n", zmq_strerror(errno));
    }
    if (zmq_connect(ret->from_socket, addr2) == -1) {
        LOG_ERR("zmq_connect(): %s\n", zmq_strerror(errno));
    }
    // else {
    //     if (zmq_bind(ret->from_socket, addr1) == -1) {
    //         fprintf(stderr, "zmq_bind(): %s\n", zmq_strerror(errno));
    //     }
    //     if (zmq_bind(ret->to_socket, addr2) == -1) {
    //         fprintf(stderr, "zmq_bind(): %s\n", zmq_strerror(errno));
    //     }
    // }

    return ret;
}

void zmq_host_channel_free(zmq_host_channel_t *channel) {
    if (zmq_close(channel->from_socket) == -1)
        LOG_ERR("zmq_close(): %s\n", zmq_strerror(errno));
    if (zmq_close(channel->to_socket) == -1)
        LOG_ERR("zmq_close(): %s\n", zmq_strerror(errno));
    if (zmq_ctx_destroy(channel->zmq_ctx) == -1)
        LOG_ERR("zmq_ctx_destroy(): %s\n", zmq_strerror(errno));
}


zmq_controller_channel_t* zmq_controller_channel_init(const char *server, uint32_t n_host) {
    zmq_controller_channel_t* ret = (zmq_controller_channel_t*)calloc(1, sizeof(zmq_controller_channel_t));
    if (ret == NULL) {
        LOG_ERR("zmq channel allocate error\n");
    }
    ret->n_host = n_host;

    ret->zmq_ctx = zmq_ctx_new();
    if (ret->zmq_ctx == 0) {
        LOG_ERR("zmq_ctx_new(): %s\n", zmq_strerror(errno));
    }
    // if (zmq_ctx_set(ret->zmq_ctx, ZMQ_IO_THREADS, 1) == -1) {
    //     LOG_ERR("zmq_ctx_set(): %s\n", zmq_strerror(errno));
    // }

    char addr[50];
    ret->listen_socket = zmq_socket(ret->zmq_ctx, ZMQ_PULL);
    sprintf(addr, "%s:%d", server, 9000);
    LOG_MSG("addr %s\n", addr);
    if (zmq_bind(ret->listen_socket, addr) == -1) {
        LOG_ERR("zmq_bind(): %s\n", zmq_strerror(errno));
    }
    LOG_MSG("nhost %d\n", n_host);
    ret->send_socket = (void**)calloc(n_host, sizeof(void*));
    for (int i=0; i<n_host; i++) {
        ret->send_socket[i] = zmq_socket(ret->zmq_ctx, ZMQ_PUSH);
        sprintf(addr, "%s:%d", server, 9001+i);
        if (zmq_bind(ret->send_socket[i], addr) == -1) {
            LOG_ERR("zmq_bind(): %s\n", zmq_strerror(errno));
        }
        LOG_MSG("create socket %d\n", i);
    }

    return ret;
}

void zmq_controller_channel_free(zmq_controller_channel_t *channel) {
    if (zmq_close(channel->listen_socket) == -1)
        LOG_ERR("zmq_close(): %s\n", zmq_strerror(errno));
    for (int i = 0; i < channel->n_host; i++) {
        if (zmq_close(channel->send_socket[i]) == -1)
            LOG_ERR("zmq_close(): %s\n", zmq_strerror(errno));
    }
    free(channel->send_socket);
    if (zmq_ctx_destroy(channel->zmq_ctx) == -1)
        LOG_ERR("zmq_ctx_destroy(): %s\n", zmq_strerror(errno));
}

void zmq_host_recv(zmq_host_channel_t* channel, msg_t* msg) {
    if (zmq_recv(channel->from_socket, msg, sizeof(msg_t), 0) != -1) {
    }
    else {
        LOG_ERR("zmq_recv(): %s\n", zmq_strerror(errno));
    }
}

//SJB **
void zmq_host_recv_large(zmq_host_channel_t* channel, large_msg_t* msg) {
    char temp[8192];
    uint32_t total_recv = 0;
    uint32_t len;
    len = zmq_recv(channel->from_socket, temp, sizeof(temp), 0);
    memcpy((uint8_t *)msg + total_recv,temp,sizeof(temp));
    total_recv += len;
    uint32_t msg_length = ((large_msg_t*)temp)->size + 12;
    while(total_recv < msg_length){
        len = zmq_recv(channel->from_socket, temp, sizeof(temp), 0);
        if(len <= 0)
            continue;
        if(len>0){
            memcpy((uint8_t *)msg + total_recv,temp,sizeof(temp));
            total_recv += len;
            LOG_DEBUG("recv data: %d, total : %d",len,total_recv);
        }
    }
    if(total_recv != msg_length){
        LOG_DEBUG("total_recv %d not equal to msg len %d\n",total_recv,msg_length);
    }
/*    if (zmq_recv(channel->from_socket, msg, sizeof(temp), 0) != -1) {
    }
    else {
        LOG_ERR("zmq_recv(): %s\n", zmq_strerror(errno));
    }
*/
}
//SJB
int zmq_host_recv_nowait(zmq_host_channel_t* channel, msg_t* msg) {
    if (zmq_recv(channel->from_socket, msg, sizeof(msg_t), ZMQ_DONTWAIT) != -1) {
        return 0;
    }
    else if (errno == EAGAIN) {
    }
    else {
        LOG_ERR("zmq_recv(): %s\n", zmq_strerror(errno));
    }
    return -1;
}

void zmq_host_send(zmq_host_channel_t* channel, msg_t* msg) {
    uint32_t actual_size = msg->size + sizeof(uint32_t)*2 + sizeof(enum MSG_T);
    if (zmq_send(channel->to_socket, msg, actual_size, 0) != -1) {
    }
    else {
        LOG_ERR("zmq_send(): %s\n", zmq_strerror(errno));
    }
}

void zmq_controller_recv(zmq_controller_channel_t* channel, msg_t* msg) {
    if (zmq_recv(channel->listen_socket, msg, sizeof(msg_t), 0) != -1) {
    }
    else {
        LOG_ERR("zmq_recv(): %s\n", zmq_strerror(errno));
    }
}

void zmq_controller_send(zmq_controller_channel_t* channel, msg_t* msg, uint32_t host_id) {
    uint32_t actual_size = msg->size + sizeof(uint32_t)*2 + sizeof(enum MSG_T);
    uint64_t length;
    length = zmq_send(channel->send_socket[host_id-1], msg, actual_size, 0);
    if (length != -1) {
        LOG_DEBUG("zmq_send(): %ld\n",length);
    }
    else {
        LOG_ERR("zmq_send(): %s\n", zmq_strerror(errno));
    }
}


void msg_encode_new_flow_req(msg_t* msg) {
    msg->type = MSG_NEW_FLOW;
    msg->size = 0;
}

void msg_endoce_new_flow_res(const uint32_t* values, uint32_t n, large_msg_t* msg) {
    msg->type = MSG_NEW_FLOW;
    if (n >= MAX_LARGE_DATA / sizeof(uint32_t)) {
        n = MAX_LARGE_DATA / sizeof(uint32_t);
    }
    msg->size = n*sizeof(uint32_t);
    uint32_t* data = (uint32_t*)msg->data;
    for (uint32_t i=0; i<n; i++) {
        data[i] = values[i];
    }
}

void msg_decode_new_flow_res(uint32_t* index1, uint32_t* index2, uint32_t *n_ret, large_msg_t* msg) {
    uint32_t n = msg->size / sizeof(uint64_t);
    //LOG_DEBUG("n value: %d, n_ret value %d\n",n,*n_ret);
    if (n < *n_ret) {
        n = *n_ret;
    }
    else {
        *n_ret = n;
    }
    uint32_t* data = (uint32_t*)msg->data;
    uint32_t i;
    for (i=0; i<n; i++) {
        index1[i] = data[i] / ARRAY_LENGTH;
        index2[i] = data[i] % ARRAY_LENGTH;
        //LOG_MSG("%d %u %u\n", i, index1[i], index2[i]);
    }
}

void msg_encode_sync(uint32_t version, msg_t* msg) {
    msg->type = MSG_SYNC;
    msg->size = sizeof(uint32_t);
    uint32_t* data = (uint32_t*)msg->data;
    data[0] = version;
}

void msg_decode_sync(uint32_t* version, msg_t* msg) {
    uint32_t* data = (uint32_t*)msg->data;
    *version = data[0];
}


// SJB **

void msg_encode_host_data(const char* host_data,  int len, host_msg_t* msg, ominimon_header_t o_header);
void msg_decode_host_data(char* host_data,  int * len, host_msg_t* msg, ominimon_header_t *o_header);

void msg_encode_host_data(const char* host_data, int len, host_msg_t* msg, ominimon_header_t o_header){
    msg->type = MSG_HOST_DATA;
    msg->size = len;
    msg->o_header.index1 = o_header.index1;
    msg->o_header.index2 = o_header.index2;
    msg->o_header.position = o_header.position;
    msg->o_header.version = o_header.version;
    memcpy(msg->data,host_data,msg->size);
}

void msg_decode_host_data(char* host_data, int *len, host_msg_t* msg, ominimon_header_t *o_header){
    *len = msg->size;
    o_header->index1 = msg->o_header.index1;
    o_header->index2 = msg->o_header.index2;
    o_header->position = msg->o_header.position;
    o_header->version = msg->o_header.version;
    memcpy(host_data,msg->data,msg->size);
}

// SJB

void* create_dummy_channel();
void* create_rb_channel();
void* create_zmq_channel();

void send_dummy_channel(msg_t* msg);
void send_rb_channel(msg_t* msg);
void send_zmq_channel(msg_t* msg);

void recv_dummy_channel(msg_t* msg);
void recv_rb_channel(msg_t* msg);
void recv_zmq_channel(msg_t* msg);

void destroy_dummy_channel();
void destroy_rb_channel();
void destroy_zmq_channel();

#endif //ULTRAMON_CHANNEL_H
