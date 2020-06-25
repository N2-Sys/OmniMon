//
// Created by qhuang on 12/9/18.
//

#include "channel.h"
#include "include/config.h"
#include "include/hash.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>

extern conf_t* conf;

mtcp_controller_channel_t* channel = NULL;
const uint32_t n_host = 2;
uint32_t end_host = 0;


msg_t recv_msg;
msg_t send_msg;
large_msg_t send_large_msg;

uint32_t latest_epoch = 0;

#define max_sync 1024
uint64_t sync_start[max_sync];
uint64_t sync_latest[max_sync];

uint8_t used_index[INDEX_RANGE];
uint32_t index_values[MAX_HOST_INDEX];
uint32_t n_index;


void notify_start() {
    send_msg.size = 5;
    sprintf(send_msg.data, "start");
    for (uint32_t i=1; i <= n_host; i++) {
        mtcp_controller_send(channel, &send_msg, i);
    } 

}

void notify_end() {
    send_msg.type = MSG_END;
    send_msg.size = 0;
    for (uint32_t i=1; i <= n_host; i++) {
        mtcp_controller_send(channel, &send_msg, i);
    } 
}

void process_new_flow(msg_t* msg, int sockid) {
    n_index = 0;
    for (uint32_t i=0; i<MAX_HOST_INDEX; i++) {
        uint64_t key = msg->host_id * INDEX_RANGE + i;
        uint32_t index = (uint32_t)MurmurHash64A(&key, sizeof(uint64_t), 0xdeadbeef) % INDEX_RANGE;
        while (used_index[index]==1) {
            index = (index+1) % INDEX_RANGE;
        }
        index_values[n_index++] = index;
        used_index[index] = 1;
    }
    // LOG_DEBUG("MAX_HOST_INDEX: %d\n", MAX_HOST_INDEX);
    // LOG_DEBUG("u_index: %d\n", n_index);
    // LOG_DEBUG("send_large_msgs addr:%x.\n", send_large_msg);
    msg_encode_new_flow_res(index_values, n_index, &send_large_msg);
    mtcp_controller_send(channel, &send_large_msg, msg->host_id);
    
}


void process_sync(msg_t* msg, int sockid) {
    uint32_t epoch;
    msg_decode_sync(&epoch, msg);
    LOG_MSG("Receive the sync message from host %d.\n", msg->host_id);
    if (epoch<max_sync && sync_start[epoch]==0) {
        sync_start[epoch] = now_us();
    }
    if (epoch > latest_epoch) {
        LOG_MSG("Move into the new epoch %d. Broadcast the sync message.\n", epoch);
        latest_epoch = epoch;
        msg_encode_sync(epoch, &send_msg);
        for (uint32_t id=1; id<=n_host; id++) {
            mtcp_controller_send(channel, &send_msg, id);
        }
    }
    if (epoch<max_sync) {
        sync_latest[epoch] = now_us();
    }
}

typedef struct Controller {
    uint32_t process_cpu;
    uint32_t listen_port;
    uint32_t max_events;
    uint32_t n_hosts;
    uint32_t backlog;
} controller_t;


void * controller_thread(void * arg) {
    LOG_MSG("lauch the controller thread.\n");
    controller_t* ct = (controller_t*)arg;
    channel = mtcp_controller_channel_init(ct->listen_port, ct->max_events, 
        ct->process_cpu, ct->backlog, ct->n_hosts);
    uint32_t is_end = 0;
    uint32_t ready_host = 0;

    struct mtcp_epoll_event *events = (struct mtcp_epoll_event *)
			calloc(ct->max_events, sizeof(struct mtcp_epoll_event));
	if (!events) {
		LOG_ERR("Failed to create event struct!\n");
	}

    int nevents;
    int do_accept;
    while (1) {
        // LOG_DEBUG("before wait: mtcx %x\n", channel->mtcp_ctx);
		nevents = mtcp_epoll_wait(channel->mtcp_ctx, channel->ep, events, 
            ct->max_events, -1);
        // LOG_DEBUG("after wait: mtcx %x\n", channel->mtcp_ctx);
		if (nevents < 0) {
			if (errno != EINTR)
				//perror("mtcp_epoll_wait");
                LOG_ERR("mtcp_epoll_wait\n");
			break;
		}

		do_accept = FALSE;
        // LOG_DEBUG("channel->listener: %d\n", channel->listener);
		for (int i = 0; i < nevents; i++) {

			if (events[i].data.sockid == channel->listener) {
				/* if the event is for the listener, accept connection */
				do_accept = TRUE;
                LOG_MSG("Accept new host connection.\n");
			} else if (events[i].events & MTCP_EPOLLERR) {
                LOG_DEBUG("move in MTCP_EPOLLERR\n");
				int err;
				socklen_t len = sizeof(err);

				/* error on the connection */
				LOG_MSG("[CPU %d] Error on socket %d\n", 
						ct->process_cpu, events[i].data.sockid);
				if (mtcp_getsockopt(channel->mtcp_ctx, events[i].data.sockid, 
						SOL_SOCKET, SO_ERROR, (void *)&err, &len) == 0) {
					if (err != ETIMEDOUT) {
						LOG_ERR("Error on socket %d: %s\n", 
								events[i].data.sockid, strerror(err));
					}
				} else {
					LOG_ERR("failed to mtcp_getsockopt.\n");
				}
                mtcp_controller_channel_free(channel);
			} else if (events[i].events & MTCP_EPOLLIN) {
                // LOG_DEBUG("move in MTCP_EPOLLIN\n");
                int rd = mtcp_controller_recv(channel, &recv_msg, events[i].data.sockid);
                // LOG_DEBUG("after mtcp_controller_recv ctx:%x rd:%d\n", channel->mtcp_ctx, rd);
                if (rd > 0) {
                    switch (recv_msg.type) {
                        case MSG_NEW_FLOW:
                            process_new_flow(&recv_msg, events[i].data.sockid);
                            ready_host++;
                            if (ready_host == n_host) {
                                // LOG_DEBUG("just has one host, wait 10 second to notify start.\n");
                                sleep(3);
                                LOG_MSG("All the hosts registered.\nNotify the start msg.\n");
                                notify_start();
                            }
                            break;
                        case MSG_SYNC:
                            process_sync(&recv_msg, events[i].data.sockid);
                            break;
                        case MSG_END:
                            LOG_MSG("Receive the end message.\nNotify the end msg.\n");
                            notify_end();
                            is_end = 1;
                            break;
                    }
                }

			} else if (events[i].events & MTCP_EPOLLOUT) {

			} else {
				assert(0);
			}
		}

		/* if do_accept flag is set, accept connections */
		if (do_accept) {
			while (1) {
				int ret = mtcp_controller_accept_connection(channel);

				if (ret < 0)
					break;
			}
		}

        if (is_end) {
            break;
        }

	}
}

int main (int argc, char *argv []) {

    if (argc != 2) {
        fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
        exit(-1);
    }

    conf = Config_Init(argv[1]);
    
    // initialize mtcp env
    // const char* mtcp_conf_file = conf_controller_mtcp_conf_file(conf);
    const char* project_path = conf_common_project_path(conf);
    char tmp[100];
    sprintf(tmp, "%s/config/mtcp_om_controller.conf", project_path);
    uint32_t process_cpu = conf_controller_process_cpu(conf);
    uint32_t listen_port = conf_controller_listen_port(conf);
    uint32_t max_events = conf_controller_max_events(conf);
    uint32_t backlog = conf_controller_backlog(conf);
    
    controller_t* controller = (controller_t*) calloc(1, sizeof(controller_t));
    if (controller == NULL) {
        LOG_ERR("allocate controller fail.\n");
    }
    controller->backlog = backlog;
    controller->max_events = max_events;
    controller->listen_port = listen_port;
    controller->process_cpu = process_cpu;
    controller->n_hosts = n_host;
    /** 
     * it is important that core limit is set before mtcp_init() is called. 
     * You can not set core_limit after mtcp_init()
     */
    struct mtcp_conf mcfg;
    mtcp_getconf(&mcfg);
    mcfg.num_cores = 1; //core_limit
    mtcp_setconf(&mcfg);

    LOG_MSG("Initialize the mtcp env.\n");
    int ret = mtcp_init(tmp);
	if (ret) {
		LOG_ERR("Failed to initialize mtcp.\n");
	}


    memset(sync_start, 0, sizeof(sync_start));
    memset(sync_latest, 0, sizeof(sync_latest));
    memset(used_index, 0, sizeof(used_index));

    static pthread_t ct_thread;
    pthread_create(&ct_thread, NULL, controller_thread, (void *)controller);
    pthread_join(ct_thread, NULL);

	/* destroy mtcp context: this will kill the mtcp thread */
    sleep(1);
    mtcp_controller_channel_free(channel);


    return 0;
}
