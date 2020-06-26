#ifndef __AFS_CONFIG_INCLUDED_HPP__
#define __AFS_CONFIG_INCLUDED_HPP__

#include <stdint.h>

#include <iniparser.h>

#include "util.h"

// wrap iniparser dictionary
typedef struct Config {
    dictionary* dict;
} conf_t;

// create and destroy
conf_t* Config_Init(char* ininame);
void Config_Destroy(conf_t* conf);

// Section names

#define SEC_COMM "Common:"
#define SEC_HOST "Host:"

// Default parameters: common

#define MAX_CONF_LEN 1024
#define DEF_INI_NAME "config.ini"

#define KEY_COMM_TRACE_DIR "trace_dir"
#define DEF_COMM_TRACE_DIR ""

#define KEY_COMM_TRACE_RECORD_FILE "trace_record_file"
#define DEF_COMM_TRACE_RECORD_FILE ""

#define KEY_COMM_PCAP_LIST "trace_pcap_list"
#define DEF_COMM_PCAP_LIST ""

#define KEY_COMM_TRACE_BUFSIZE "trace_bufsize"
#define DEF_COMM_TRACE_BUFSIZE 10000000

#define KEY_COMM_KEY_LEN "key_len"
#define DEF_COMM_KEY_LEN 104

#define KEY_COMM_APPRO_SAMPLE_RATE "appro_sample_rate"
#define DEF_COMM_APPRO_SAMPLE_RATE 10000

#define KEY_COMM_INTERVAL_LEN "interval_len"
#define DEF_COMM_INTERVAL_LEN 1000

#define KEY_COMM_BLOCK_PUNC "block_after_punc"
#define DEF_COMM_BLOCK_PUNC 0

#define KEY_COMM_OVS_MAX_CNT "ovs_max_cnt"
#define DEF_COMM_OVS_MAX_CNT 1

#define KEY_COMM_OVS_INTERVAL_CNT "ovs_interval_cnt"
#define DEF_COMM_OVS_INTERVAL_CNT 1

#define KEY_COMM_ALG "alg_name"
#define DEF_COMM_ALG ""

#define KEY_COMM_IS_CPU "is_pin_cpu"
#define DEF_COMM_IS_CPU 0

// Default parameters: Output analysis

#define KEY_COMM_IS_OUTPUT "is_output"
#define DEF_COMM_IS_OUTPUT 1 

#define KEY_COMM_NUM_INTERVAL "num_interval"
#define DEF_COMM_NUM_INTERVAL 1

#define KEY_COMM_ZMQ_DATA_SERVER "zmq_data_server"
#define DEF_COMM_ZMQ_DATA_SERVER ""

#define KEY_COMM_ZMQ_CMD_SERVER "zmq_cmd_server"
#define DEF_COMM_ZMQ_CMD_SERVER ""

#define KEY_COMM_REDIS_IP "redis_ip"
#define DEF_COMM_REDIS_IP ""

#define KEY_COMM_REDIS_PORT "redis_port"
#define DEF_COMM_REDIS_PORT 0

#define KEY_COMM_OVS "is_enable_ovs"
#define DEF_COMM_OVS 0

#define KEY_HOST_DPDK_ARGS "dpdk_args"
#define DEF_HOST_DPDK_ARGS ""

#define KEY_HOST_MAX_KEY "host_max_key"
#define DEF_HOST_MAX_KEY 0

// Get parameters: common

const char* conf_common_trace_dir(conf_t* conf);
const char* conf_common_record_file(conf_t* conf);
unsigned long long conf_common_trace_bufsize(conf_t* conf);
uint32_t conf_common_interval_len(conf_t* conf);

uint32_t conf_common_key_len(conf_t* conf);

const char* conf_common_zmq_data_server(conf_t* conf);

// Get parameters: output analysis

uint32_t conf_common_is_output(conf_t* conf);
int conf_common_is_pin_cpu(conf_t* conf);

char* conf_host_dpdk_args(conf_t* conf);
uint32_t conf_host_max_key(conf_t* conf);

const char* strconcat(const char* a, const char* b);

#endif
