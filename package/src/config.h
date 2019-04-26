#ifndef __CONFIG_H
#define __CONFIG_H

#include <uci.h>
extern char *config_get(const char *name);
int config_get_int(const char *name);

#define DEFAULT_SCAN_DEPTH 3


typedef struct nmap_scan_config{
	int manual;           // 自动，或者手动输入主机IP
	int scan_rate;        // 扫描频率
	int retry_count;      // 重试次数
	int scan_depth;       // 扫描深度
	int process_num;      // 并行线程数
	int timeout;     	  // 超时时间
	char ip_pool[64];        // 扫描网段池
	char port_pool[128];      // 常用端口池
}nmap_config_t;

struct nmap_scan_config g_nmap_config;

int config_get_int(const char *name)
{
    char *value = config_get(name);
    if(value[0] != '\0')
        return atoi(value);
    else
        return 0;
}

void load_config(struct nmap_scan_config *conf)
{
    conf->manual = config_get_int("manual");
    conf->scan_depth = config_get_int("scan_depth");
    conf->process_num = config_get_int("process_num");
    conf->retry_count = config_get_int("retry_count");
    conf->timeout = config_get_int("scan_timeout");
    conf->scan_rate = config_get_int("scan_rate") * 60;
    strncpy(conf->port_pool, config_get("port_pool"), sizeof(conf->port_pool) - 1);
    strncpy(conf->ip_pool, config_get("ip_pool"), sizeof(conf->ip_pool) - 1);
}

#endif // __CONFIG_H
