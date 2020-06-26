//
// Created by qhuang on 12/9/18.
//

#include "channel.h"
#include "include/config.h"
#include "include/hash.h"

extern conf_t* conf;

zmq_controller_channel_t* channel = NULL;
const uint32_t n_host = 1;
uint32_t end_host = 0;

#define DATA_SIZE 512
struct DummyType {
    unsigned number;
    char dummy[DATA_SIZE];
};
static int message_size = sizeof(struct DummyType);

msg_t recv_msg;
msg_t send_msg;
large_msg_t send_large_msg;

uint32_t latest_version = 0;

#define max_sync 1024
uint64_t sync_start[max_sync];
uint64_t sync_latest[max_sync];

uint8_t used_index[INDEX_RANGE];
uint32_t index_values[MAX_HOST_INDEX];
uint32_t n_index;

void notify_start() {
    for (uint32_t i=1; i<=n_host; i++) {
        send_msg.size = 0;
        zmq_controller_send(channel, &send_msg, i);
    }
}

void process_new_flow(msg_t* msg) {

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

    msg_endoce_new_flow_res(index_values, n_index, &send_large_msg);
    zmq_controller_send(channel, (msg_t*)(&send_large_msg), msg->host_id);
    // LOG_MSG("host id %u size %u\n", msg->host_id, msg->size);
}

void process_sync(msg_t* msg) {
    uint32_t version;
    msg_decode_sync(&version, msg);
    if (version<max_sync && sync_start[version]==0) {
        sync_start[version] = now_us();
    }
    if (version > latest_version) {
        latest_version = version;
        msg_encode_sync(version, &send_msg);
        for (uint32_t id=1; id<=n_host; id++) {
            zmq_controller_send(channel, &send_msg, id);
        }
    }
    if (version<max_sync) {
        sync_latest[version] = now_us();
    }
}

int main (int argc, char *argv []) {

    if (argc != 2) {
        fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
        exit(-1);
    }

    conf = Config_Init(argv[1]);
    const char* zmq_server = conf_common_zmq_data_server(conf);

    channel = zmq_controller_channel_init(zmq_server, n_host);
    uint32_t is_end = 0;

    memset(sync_start, 0, sizeof(sync_start));
    memset(sync_latest, 0, sizeof(sync_latest));
    memset(used_index, 0, sizeof(used_index));

    uint32_t ready_host = 0;
    while (1) {
        zmq_controller_recv(channel, &recv_msg);
        switch (recv_msg.type) {
            case MSG_NEW_FLOW:
                process_new_flow(&recv_msg);
                ready_host++;
                if (ready_host == n_host) {
                    notify_start();
                }
                break;
            case MSG_SYNC:
                process_sync(&recv_msg);
                break;
            case MSG_END:
                is_end = 1;
                break;
        }
        if (is_end) {
            break;
        }
    }

    zmq_controller_channel_free(channel);

    for (int i=0; i<max_sync; i++) {
        if (sync_start[i] > 0) {
            LOG_MSG("%u %lu %lu %lu\n", i, sync_start[i], sync_latest[i], sync_latest[i]-sync_start[i]);
        }
    }

    return 0;
}
