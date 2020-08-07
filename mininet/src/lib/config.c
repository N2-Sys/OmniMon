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

int getint(config_t* cfg, const char* sec, const char* key, int def) {
    int arg;
    if (config_lookup_int(cfg, strconcat(sec, key), &arg))
        return arg;
    else
        LOG_ERR("config %s read failed.\n", key);
}


/*
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
*/
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
        if(!config_read_file(&ret->cfg, ininame)) {
            config_destroy(&ret->cfg);
            LOG_ERR("%s:%d - %s\n", config_error_file(&ret->cfg),
                config_error_line(&ret->cfg), config_error_text(&ret->cfg));
        }
    }
    return ret;
}

void Config_Destroy(conf_t* conf) {
    if (conf == NULL)
        return;
    config_destroy(&conf->cfg);
    free(conf);
}


/*******************************************
 *
 * rountes to get config parameters (common)
 *
 ******************************************/
void conf_common_trace_dir(conf_t* conf, char ** arg) {
    if(!config_lookup_string(&conf->cfg, strconcat(SEC_COMM, KEY_COMM_TRACE_DIR), arg))
        LOG_ERR("read config %s failed.\n", KEY_COMM_TRACE_DIR);
}
void conf_common_pcap_list(conf_t* conf, char ** arg){
    if(!config_lookup_string(&conf->cfg, strconcat(SEC_COMM, KEY_COMM_PCAP_LIST), arg))
        LOG_ERR("read config %s failed.\n", KEY_COMM_PCAP_LIST);
}

uint32_t conf_common_key_len(conf_t* conf) {
    return (uint32_t)getint(&conf->cfg, SEC_COMM, KEY_COMM_KEY_LEN, DEF_COMM_KEY_LEN);
}

uint32_t conf_common_interval_len(conf_t* conf) {
    return (uint32_t)getint(&conf->cfg, SEC_COMM, KEY_COMM_INTERVAL_LEN, DEF_COMM_INTERVAL_LEN);
}

void conf_common_zmq_data_server(conf_t* conf, char ** arg) {
    if(!config_lookup_string(&conf->cfg, strconcat(SEC_COMM, KEY_COMM_ZMQ_DATA_SERVER), arg))
        LOG_ERR("read config %s failed.\n", KEY_COMM_ZMQ_DATA_SERVER);
}


void conf_host_dpdk_args(conf_t* conf, char ** arg) {
    if(!config_lookup_string(&conf->cfg, strconcat(SEC_HOST, KEY_HOST_DPDK_ARGS), arg))
        LOG_ERR("read config %s failed.\n", KEY_HOST_DPDK_ARGS);
}

uint32_t conf_host_max_key(conf_t* conf) {
    return (uint32_t)getint(&conf->cfg, SEC_HOST, KEY_HOST_MAX_KEY, DEF_HOST_MAX_KEY);
}

