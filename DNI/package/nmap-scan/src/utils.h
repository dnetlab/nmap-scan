#ifndef __UTILS_H
#define __UTILS_H

#include <stdio.h>

#include "uthash.h"
#include "cjson.h"

#define PROC_NET_ARP           ("/proc/net/arp")
#define TMP_NMAP_FILE          ("/tmp/tmp_nmapfile")
#define NMAP_CMD_FORMAT        ("nmap -T4 -sS %s -p%d")
#define UNIX_SERVER_PATH       ("/var/run/nmap-scan.sock")
#define SCAN_EATE_TIME         (10 * 60) // 10 minutes
#define CHECK_STATUS_TIMER     (1 * 60)  // 1 minutes
#define MAX_TBL_NUM            500

#define MAX_LAN_NUM            4
#define UNIX_LISTEN_NUMS       10

extern int debug_flag;

#define log_debug(fmt, args...) \
{	\
	if(debug_flag) \
		printf("[%s-%d]: "fmt, __FUNCTION__, __LINE__, ##args);\
}
#define log_error(fmt, args...) printf("[%s-%d]: "fmt, __FUNCTION__, __LINE__, ##args)

struct host_service_info{
	char status;       			//状态
	int port;         			//端口
	char protocol_type[15];     //类型
	char name[20];    			//服务名称
};

typedef struct uthash_host{
	int key;
	struct host_service_info host_service;
	UT_hash_handle hh;
}HASH_HOST_T;

struct arp_info{
	unsigned int in_ip;
	int host_status;
	char mac_addr[18];
	char device[20];
	char host_description[64];
	char os_type[128];
};

typedef struct uthash_nmap{
	unsigned int key;
	struct arp_info arp;
	HASH_HOST_T *header;
	UT_hash_handle hh;
}HASH_NMAP_T;

HASH_NMAP_T *lan_table[MAX_LAN_NUM];

struct if_map {
    int idx;
    char *device;
    char *name;
};

static struct if_map lan_maps[MAX_LAN_NUM] = {
    { .idx = 0, .device = "br0", .name = "LAN1" },
    { .idx = 1, .device = "br1", .name = "LAN2" },
    { .idx = 2, .device = "br2", .name = "LAN3" },
    { .idx = 3, .device = "br3", .name = "LAN4" },
};

struct ip_pool{
	int idx;
	char ipAddr[20];
};
struct ip_pool ip_table[MAX_LAN_NUM];

/*将整型数据转换成IP点分形式*/
char *int_to_ip(unsigned int inIp);
int get_lan_idx(char *device);
char *get_lan_name(int lan_idx);
/*更新及复制arp数据*/
void copy_arp_data(struct arp_info *dst, struct arp_info *src);
/*更新及复制host数据*/
void copy_host_data(struct     host_service_info *dst, struct host_service_info *src);

/*获取nmap表节点数*/
int get_nmap_tbl_nums(HASH_NMAP_T *tbl);
/*获取host表节点数*/
int get_host_tbl_nums(HASH_HOST_T *tbl);
/*在nmap表添加节点*/
int add_node_to_nmap_table(struct arp_info arp, HASH_NMAP_T **tbl);
/*在host表添加节点*/
int add_node_to_host_table(struct host_service_info service_info, HASH_HOST_T **tbl);
/*根据key获取nmap表节点*/
HASH_NMAP_T *find_nmap_node_by_key(unsigned int key, HASH_NMAP_T *tbl);
/*根据key获取host表节点*/
HASH_HOST_T *find_host_node_by_key(int key, HASH_HOST_T *tbl);
/*销毁host表*/
void destroy_host_table(HASH_HOST_T **tbl);
/*销毁链表*/
void destroy_table(HASH_NMAP_T **tbl);
/*删除nmap表节点*/
int delete_nmap_tbl_node(unsigned int key, HASH_NMAP_T **tbl);
/*删除host表节点*/
int delete_host_tbl_node(int key, HASH_HOST_T **tbl);
/*更新nmap表节点信息*/
void update_nmap_tbl_info(struct arp_info arp, HASH_NMAP_T *P);
/*更新host表节点信息*/
void update_host_tbl_info(struct host_service_info service_info, HASH_HOST_T *P);
void dump_host_tbl_data(HASH_HOST_T *tbl);
/*打印表所有数据*/
void dump_tbl_data(HASH_NMAP_T *tbl);

int cjson_get_int(cJSON *obj, char *key, int *val);
int cjson_get_double(cJSON *obj, char *key, double *val);
char *cjson_get_string(cJSON *obj, char *key);

#endif // __UTILS_H
