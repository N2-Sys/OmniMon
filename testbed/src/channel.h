//
// Created by qhuang on 11/21/18.
//

#ifndef __OMNIMON_CHANNEL_H__
#define __OMNIMON_CHANNEL_H__

#include <sys/socket.h>
#include <netinet/in.h>

#include <mtcp_api.h>
#include <mtcp_epoll.h>
#include <rte_eal.h>
#include <rte_malloc.h>

#include "packet.h"
#include "include/util.h"


enum MSG_T {MSG_NEW_FLOW, MSG_HOST_DATA, MSG_SYNC, MSG_END};
#define MAX_MSG_DATA 16
#define IP_RANGE 1
#define HOST_NUM 128
#define ARRAY_LENGTH 512
#define INDEX_RANGE (ARRAY_LENGTH*ARRAY_LENGTH)
#define MAX_HOST_INDEX (INDEX_RANGE / HOST_NUM)
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

/*************************************************
 ***************** MTCP CHANNEL ******************
 ************************************************/

typedef struct MTCPHostChannel {
    mctx_t mtcp_ctx;
    int ep;
    int sockid;
    // struct mtcp_epoll_event* events;
    // void* to_socket;
    // void* from_socket;
} mtcp_host_channel_t;


typedef struct MTCPControllerChannel {
    mctx_t mtcp_ctx;
    int ep;
    int listener;
    uint32_t n_host;
    void** registered_hosts;
    uint32_t connected_hosts;
    uint32_t max_hosts;
} mtcp_controller_channel_t;

mtcp_host_channel_t* mtcp_host_channel_init(const char* controller_ip, uint32_t listen_port, uint32_t max_events, uint32_t process_cpu) {
    mtcp_host_channel_t* ret = (mtcp_host_channel_t*)calloc(1, sizeof(mtcp_host_channel_t));
    if (ret == NULL) {
        LOG_ERR("mtcp channel allocate error\n");
    }
    LOG_MSG("Create the mtcp context.\n");
    ret->mtcp_ctx = mtcp_create_context(process_cpu);

    LOG_MSG("Init NIC rss.\n");
    in_addr_t daddr = inet_addr(controller_ip);
    in_port_t dport = htons(listen_port);
    in_addr_t saddr = INADDR_ANY;
	mtcp_init_rss(ret->mtcp_ctx, saddr, IP_RANGE, daddr, dport);

	int ep = mtcp_epoll_create(ret->mtcp_ctx, max_events);
	if (ep < 0) {
		LOG_ERR("Failed to create epoll struct!\n");
	}
    ret->ep = ep;

    LOG_MSG("Create mtcp socket.\n");
	int sockid = mtcp_socket(ret->mtcp_ctx, AF_INET, SOCK_STREAM, 0);
	if (sockid < 0) {
		LOG_ERR("Failed to create socket!\n");
	}
	int res = mtcp_setsock_nonblock(ret->mtcp_ctx, sockid);
	if (res < 0) {
		LOG_ERR("Failed to set socket in nonblocking mode.\n");
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = daddr;
	addr.sin_port = dport;
	
    LOG_MSG("Connect to mtcp server.\n");
	res = mtcp_connect(ret->mtcp_ctx, sockid, 
			(struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if (res < 0) {
		if (errno != EINPROGRESS) {
			mtcp_close(ret->mtcp_ctx, sockid);
            LOG_ERR("Fail to connect to mtcp controller.\n");
			return -1;
		}
	}
    LOG_MSG("Connected to mtcp server.\n");
    ret->sockid = sockid;
    return ret;
}


mtcp_controller_channel_t* mtcp_controller_channel_init(uint32_t listen_port, 
    uint32_t max_events, uint32_t process_cpu, uint32_t backlog, uint32_t hosts_num) {
    mtcp_controller_channel_t* ret = (mtcp_controller_channel_t*)
        calloc(1, sizeof(mtcp_controller_channel_t));
    if (ret == NULL) {
        LOG_ERR("controller mtcp channel allocate error\n");
    }
    // mtcp_core_affinitize(process_cpu);
    /* create mtcp context: this will spawn an mtcp thread */
    LOG_MSG("Create the mtcp context. process_cpu: %d\n", process_cpu);
    ret->mtcp_ctx = mtcp_create_context(process_cpu);
    if (!ret->mtcp_ctx) {
		LOG_ERR("Failed to create mtcp context.\n");
    }

    // LOG_DEBUG("ret->mtcp_ctx in init: %x\n", ret->mtcp_ctx);

    /* create epoll descriptor */
    LOG_MSG("Create the mtcp epoll descriptor.\n");
	ret->ep = mtcp_epoll_create(ret->mtcp_ctx, max_events);
	if (ret->ep < 0) {
		mtcp_destroy_context(ret->mtcp_ctx);
        free(ret);
		LOG_ERR("Failed to create epoll descriptor!\n");
	}

    LOG_MSG("Create the mtcp listenind socket.\n");
    ret->listener = mtcp_socket(ret->mtcp_ctx, AF_INET, SOCK_STREAM, 0);
	if (ret->listener < 0) {
		LOG_ERR("Failed to create listening socket!\n");
	}
    LOG_MSG("Set the mtcp listenind socket in nonblocking mode.\n");
	int res = mtcp_setsock_nonblock(ret->mtcp_ctx, ret->listener);
	if (res < 0) {
		LOG_ERR("Failed to set socket in nonblocking mode.\n");
	}
	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(listen_port);
    LOG_MSG("Bind the mtcp listenind socket to Port %d\n", listen_port);
	res = mtcp_bind(ret->mtcp_ctx, ret->listener, 
			(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (res < 0) {
		LOG_ERR("Failed to bind to the listening socket!\n");
	}

	/* listen (backlog: can be configured) */
	res = mtcp_listen(ret->mtcp_ctx, ret->listener, backlog);
	if (res < 0) {
		LOG_ERR("mtcp_listen() failed!\n");
	}

    ret->registered_hosts = (void**)calloc(hosts_num, sizeof(void*));
    ret->connected_hosts = 0;
    ret->max_hosts = hosts_num;
	
	/* wait for incoming accept events */
    LOG_MSG("Wait for incoming host resgiter.\n");
    struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = ret->listener;
	mtcp_epoll_ctl(ret->mtcp_ctx, ret->ep, MTCP_EPOLL_CTL_ADD, 
        ret->listener, &ev);
    return ret;
    
}

void mtcp_host_send(mtcp_host_channel_t* channel, msg_t* msg, int sockid) {
    int actual_size = msg->size + sizeof(uint32_t)*2 + sizeof(enum MSG_T);
    //uint32_t actual_size = msg->size + sizeof(uint32_t)*2 + sizeof(enum MSG_T);

	int wr = mtcp_write(channel->mtcp_ctx, sockid, msg, actual_size);
	if (wr < actual_size) {
		LOG_ERR("Socket %d: Sending msg failed. "
				"try: %d, sent: %d\n", channel->sockid, actual_size, wr);
	}
    // LOG_DEBUG("mtcp_host_send size: %d\n", wr);

}


void mtcp_host_recv(mtcp_host_channel_t* channel, msg_t* msg, int sockid) {
    // LOG_DEBUG("sizeof(msg_t): %d\n", sizeof(msg_t));
    int rd = mtcp_read(channel->mtcp_ctx, sockid, msg, sizeof(msg_t));
	if (rd < 0) {
        mtcp_epoll_ctl(channel->mtcp_ctx, channel->ep, 
            MTCP_EPOLL_CTL_DEL, channel->sockid, NULL);
        mtcp_close(channel->mtcp_ctx, channel->sockid);
        LOG_ERR("Failed to recv mtcp msg.\n");
	}

}

void mtcp_host_recv_large(mtcp_host_channel_t* channel, large_msg_t* msg, int sockid) {
    char tmp[8192];
    //LOG_DEBUG("large_msg_size: %d\n", sizeof(large_msg_t));
    int total;
    int rd = mtcp_read(channel->mtcp_ctx, sockid, tmp, sizeof(tmp));
    //LOG_DEBUG("first receive large message read %d bytes.\n", rd);
	if (rd < 0) {
        mtcp_epoll_ctl(channel->mtcp_ctx, channel->ep, 
            MTCP_EPOLL_CTL_DEL, channel->sockid, NULL);
        mtcp_close(channel->mtcp_ctx, channel->sockid);
        LOG_ERR("Failed to recv large msg.\n");
	}
    
	struct mtcp_epoll_event ev;
    ev.events = MTCP_EPOLLNONE;
    ev.data.sockid = sockid;
    mtcp_epoll_ctl(channel->mtcp_ctx, channel->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);
    total = rd;
    memcpy(msg, tmp, rd);
    uint32_t actual_size = msg->size + sizeof(uint32_t)*2 + sizeof(enum MSG_T);
    while (total < actual_size) {
        rd = mtcp_read(channel->mtcp_ctx, sockid, tmp, sizeof(tmp));
        // if (rd > 0)
        //     LOG_DEBUG("in while receive large message read %d bytes.\n", rd);
        if (rd < 0)
            continue;
        memcpy((uint8_t*)((uint8_t*)msg+total), tmp, rd);
        total += rd;
    }
    if (total != actual_size) {
        LOG_ERR("Failed to recv large msg, the message should be %d receive %d.\n",
            actual_size, total);
    }
    ev.events = MTCP_EPOLLIN;
    mtcp_epoll_ctl(channel->mtcp_ctx, channel->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);
    // LOG_DEBUG("host recv large msg size: %d\n", total);
}

void mtcp_controller_channel_free(mtcp_controller_channel_t *channel) {
    mtcp_epoll_ctl(channel->mtcp_ctx, channel->ep, MTCP_EPOLL_CTL_DEL, 
        channel->listener, NULL);
	mtcp_close(channel->mtcp_ctx, channel->listener);
    free(channel);
}

int mtcp_controller_accept_connection(mtcp_controller_channel_t *channel) {
	struct mtcp_epoll_event ev;

	int c = mtcp_accept(channel->mtcp_ctx, channel->listener, NULL, NULL);
	if (c >= 0) {
		if (c >= channel->max_hosts + 2) {
			LOG_MSG("Invalid socket id %d.\n", c);
			return -1;
		}
        channel->registered_hosts[channel->connected_hosts++] = c;
        LOG_MSG("New connection accepted sockid: %d.\n", c);
		ev.events = MTCP_EPOLLIN;
		ev.data.sockid = c;
		mtcp_setsock_nonblock(channel->mtcp_ctx, c);
		mtcp_epoll_ctl(channel->mtcp_ctx, channel->ep, MTCP_EPOLL_CTL_ADD, c, &ev);
	} else {
		if (errno != EAGAIN) {
			LOG_MSG("mtcp_accept() error %s\n", 
					strerror(errno));
		}
	}
	return c;
}

int mtcp_controller_recv(mtcp_controller_channel_t* channel, msg_t* msg, int sockid) {
    int rd = mtcp_read(channel->mtcp_ctx, sockid, msg, sizeof(msg_t));
    // LOG_DEBUG("sizeof(msg_t): %d\n", sizeof(msg_t));
    if (rd < 0) {
        /* if not EAGAIN, it's an error */
        if (errno != EAGAIN) {
            mtcp_controller_channel_free(channel);
        }
    }
    return rd;
}

void mtcp_controller_send(mtcp_controller_channel_t* channel, msg_t* msg, uint32_t host_id) {
    int actual_size = msg->size + sizeof(uint32_t)*2 + sizeof(enum MSG_T);

    int wr = mtcp_write(channel->mtcp_ctx, channel->registered_hosts[host_id-1], msg, actual_size);
	if (wr < actual_size) {
		LOG_ERR("Socket %d: Sending msg failed. "
				"try: %d, sent: %d\n", channel->registered_hosts[host_id-1], actual_size, wr);
	}
    // LOG_DEBUG("mtcp_controller send msg size: %d\n", wr);
}

void msg_encode_new_flow_req(msg_t* msg) {
    msg->type = MSG_NEW_FLOW;
    msg->size = 0;
}

void msg_encode_new_flow_res(const uint32_t* values, uint32_t n, large_msg_t* msg) {
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
    if (n < *n_ret) {
        n = *n_ret;
    }
    else {
        *n_ret = n;
    }
    uint32_t* data = (uint32_t*)msg->data;
    for (uint32_t i=0; i<n; i++) {
        index1[i] = data[i] / ARRAY_LENGTH;
        index2[i] = data[i] % ARRAY_LENGTH;
    }

}

void msg_encode_sync(uint32_t epoch, msg_t* msg) {
    msg->type = MSG_SYNC;
    msg->size = sizeof(uint32_t);
    uint32_t* data = (uint32_t*)msg->data;
    data[0] = epoch;
}

void msg_decode_sync(uint32_t* epoch, msg_t* msg) {
    uint32_t* data = (uint32_t*)msg->data;
    *epoch = data[0];
}

void msg_encode_host_data(void* host_data, int host_id, msg_t* msg);
void msg_decode_host_data(void* host_data, int* host_id, msg_t* msg);


#endif //__OMNIMON_CHANNEL_H__
