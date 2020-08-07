#ifndef __AFS_CONFIG_INCLUDED_HPP__
#define __AFS_CONFIG_INCLUDED_HPP__

#include <stdint.h>

#include <libconfig.h>

#include "util.h"

// wrap iniparser dictionary
typedef struct Config {
    config_t cfg;
} conf_t;

// create and destroy
conf_t* Config_Init(char* ininame);
void Config_Destroy(conf_t* conf);

// Section names

#define SEC_COMM "Common."
#define SEC_HOST "Host."

// Default parameters: common

#define MAX_CONF_LEN 1024
#define DEF_INI_NAME "config.ini"

#define KEY_COMM_TRACE_DIR "trace_dir"
#define DEF_COMM_TRACE_DIR ""

#define KEY_COMM_PCAP_LIST "trace_pcap_list"
#define DEF_COMM_PCAP_LIST ""

#define KEY_COMM_KEY_LEN "key_len"
#define DEF_COMM_KEY_LEN 104

#define KEY_COMM_INTERVAL_LEN "interval_len"
#define DEF_COMM_INTERVAL_LEN 1000

#define KEY_COMM_ZMQ_DATA_SERVER "zmq_data_server"
#define DEF_COMM_ZMQ_DATA_SERVER ""

#define KEY_HOST_DPDK_ARGS "dpdk_args"
#define DEF_HOST_DPDK_ARGS ""

#define KEY_HOST_MAX_KEY "host_max_key"
#define DEF_HOST_MAX_KEY 0

// Get parameters: common

void conf_common_trace_dir(conf_t*, char**);
void conf_common_pcap_list(conf_t*, char**);
uint32_t conf_common_interval_len(conf_t* conf);
uint32_t conf_common_key_len(conf_t* conf);
void conf_common_zmq_data_server(conf_t*, char**);

// Get parameters: output analysis

void conf_host_dpdk_args(conf_t*, char**);
uint32_t conf_host_max_key(conf_t* conf);

const char* strconcat(const char* a, const char* b);

#endif
