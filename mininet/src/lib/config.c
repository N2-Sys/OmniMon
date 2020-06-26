#include <string.h>

#include "include/config.h"

const char* strconcat(const char* a, const char* b) {
    static char l[MAX_CONF_LEN+1];

    if (a == NULL)
        return b;
    if (b == NULL)
        return NULL;

    if (strlen(a) + strlen(b) >= MAX_CONF_LEN) {
        LOG_ERR("error: concat names too long\n");
    }

    strcpy(l, a);
    strcat(l, b);

    return l;
}

/*****************
 * 
 * Wrap iniparser
 *
 ****************/

void check_instance() {
    /*
    if (conf == NULL) {
        conf = Config_Init(NULL);
    }
    */
}

char* getstring( dictionary* dict, const char* sec, const char* key, const char* def) {
    check_instance();
    return (char*)iniparser_getstring(dict, strconcat(sec, key), (char*)def);
}

int getint(dictionary* dict, const char* sec, const char* key, int def) {
    check_instance();
    return iniparser_getint(dict, strconcat(sec, key), def);
}

unsigned long long getull(dictionary* dict, const char* sec, const char* key, 
        unsigned long long def) {

    check_instance();
    const char* str = iniparser_getstring(dict, strconcat(sec, key), NULL);
    if (str == NULL) return def;
    return strtoull(str, NULL, 10);
}

double getdouble(dictionary* dict, const char* sec, const char* key, double def) {
    check_instance();
    return iniparser_getdouble(dict, strconcat(sec, key), def);
}

int getboolean(dictionary* dict, const char* sec, const char* key, int def) {
    check_instance();
    return iniparser_getboolean(dict, strconcat(sec, key), def);
}

/********************
 *
 * Create and Destroy
 *
 *******************/

conf_t* Config_Init(char* ininame) {

    conf_t* ret = (conf_t*)calloc(1, sizeof(conf_t));
    if (ret == NULL)
        LOG_ERR("error: allocate config error\n");

    if (ininame) {
        ret->dict = iniparser_load(ininame);
    }
    else {
        ret->dict = iniparser_load(DEF_INI_NAME);
    }

    if (ret->dict == 0) {
        LOG_ERR("error: iniparser_load()\n");
    }

    return ret;
}

void Config_Destroy(conf_t* conf) {
    if (conf == NULL)
        return;

    if (conf->dict) {
        iniparser_freedict(conf->dict);
    }
    free(conf);
}

/*******************************************
 *
 * rountes to get config parameters (common)
 *
 ******************************************/

const char* conf_common_trace_dir(conf_t* conf) {
    return getstring(conf->dict, SEC_COMM, KEY_COMM_TRACE_DIR, DEF_COMM_TRACE_DIR);
}

const char* conf_common_record_file(conf_t* conf) {
    return getstring(conf->dict, SEC_COMM, KEY_COMM_TRACE_RECORD_FILE, DEF_COMM_TRACE_RECORD_FILE);
}

const char* conf_common_pcap_list(conf_t* conf) {
    return getstring(conf->dict, SEC_COMM, KEY_COMM_PCAP_LIST, DEF_COMM_PCAP_LIST);
}

unsigned long long conf_common_trace_bufsize(conf_t* conf) {
    return getull(conf->dict, SEC_COMM, KEY_COMM_TRACE_BUFSIZE, DEF_COMM_TRACE_BUFSIZE);
}

uint32_t conf_common_key_len(conf_t* conf) {
    return (uint32_t)getull(conf->dict, SEC_COMM, KEY_COMM_KEY_LEN, DEF_COMM_KEY_LEN);
}

unsigned long long conf_common_appro_sample_rate(conf_t* conf) {
    return getull(conf->dict, SEC_COMM,
            KEY_COMM_APPRO_SAMPLE_RATE,
            DEF_COMM_APPRO_SAMPLE_RATE);
}

uint32_t conf_common_interval_len(conf_t* conf) {
    return (uint32_t)getull(conf->dict, SEC_COMM,
            KEY_COMM_INTERVAL_LEN,
            DEF_COMM_INTERVAL_LEN);
}

int conf_common_block_punc(conf_t* conf) {
    return getint(conf->dict, SEC_COMM, KEY_COMM_BLOCK_PUNC, DEF_COMM_BLOCK_PUNC);
}

unsigned long long conf_common_ovs_max_cnt(conf_t* conf) {
    return getull(conf->dict, SEC_COMM,
            KEY_COMM_OVS_MAX_CNT,
            DEF_COMM_OVS_MAX_CNT);
}

unsigned long long conf_common_ovs_interval_cnt(conf_t* conf) {
    return getull(conf->dict, SEC_COMM,
            KEY_COMM_OVS_INTERVAL_CNT,
            DEF_COMM_OVS_INTERVAL_CNT);
}

/*******************************************
 *
 * rountes to get config parameters (output analysis)
 *
 ******************************************/

uint32_t conf_common_is_output(conf_t* conf) {
    return (uint32_t)getull(conf->dict, SEC_COMM,
            KEY_COMM_IS_OUTPUT,
            DEF_COMM_IS_OUTPUT);
}

int conf_common_is_pin_cpu(conf_t* conf) {
    return getull(conf->dict, SEC_COMM,
            KEY_COMM_IS_CPU,
            DEF_COMM_IS_CPU);
}

unsigned long long conf_common_num_interval(conf_t* conf) {
    return getull(conf->dict, SEC_COMM,
            KEY_COMM_NUM_INTERVAL,
            DEF_COMM_NUM_INTERVAL);
}

const char* conf_common_alg(conf_t* conf) {
    return getstring(conf->dict, SEC_COMM,
            KEY_COMM_ALG, DEF_COMM_ALG);
}

const char* conf_common_zmq_data_server(conf_t* conf) {
    return getstring(conf->dict, SEC_COMM,
            KEY_COMM_ZMQ_DATA_SERVER, DEF_COMM_ZMQ_DATA_SERVER);
}

const char* conf_common_zmq_cmd_server(conf_t* conf) {
    return getstring(conf->dict, SEC_COMM,
            KEY_COMM_ZMQ_CMD_SERVER, DEF_COMM_ZMQ_CMD_SERVER);
}

const char* conf_common_redis_ip(conf_t* conf) {
    return getstring(conf->dict, SEC_COMM,
            KEY_COMM_REDIS_IP, DEF_COMM_REDIS_IP);
}

int conf_common_redis_port(conf_t* conf) {
    return getint(conf->dict, SEC_COMM,
            KEY_COMM_REDIS_PORT, DEF_COMM_REDIS_PORT);
}

int conf_common_is_enable_ovs(conf_t* conf) {
    return getint(conf->dict, SEC_COMM,
            KEY_COMM_OVS, DEF_COMM_OVS);
}

char* conf_host_dpdk_args(conf_t* conf) {
    return getstring(conf->dict, SEC_HOST,
                     KEY_HOST_DPDK_ARGS, DEF_HOST_DPDK_ARGS);
}

uint32_t conf_host_max_key(conf_t* conf) {
    return (uint32_t)getull(conf->dict, SEC_HOST,
                  KEY_HOST_MAX_KEY, DEF_HOST_MAX_KEY);
}
