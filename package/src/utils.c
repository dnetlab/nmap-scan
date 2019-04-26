#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils.h"

/*将整型数据转换成IP点分形式*/
char *int_to_ip(unsigned int inIp)
{
	struct in_addr addr;
	addr.s_addr = inIp;
	return inet_ntoa(addr);
}

int get_lan_idx(char *device)
{
	int i = 0;
 
	for(i = 0; i < MAX_LAN_NUM; i ++)
	{
		if(strcmp(device, lan_maps[i].device) == 0)
		{
			return lan_maps[i].idx;
		}
	}
 
	return -1;
}
 
char *get_lan_name(int lan_idx)
{
	int i = 0;
 
	for(i = 0; i < MAX_LAN_NUM; i ++)
	{
		if(lan_idx == lan_maps[i].idx)
		{
			return lan_maps[i].name;
		}
	}
 
	return NULL;
}

/*更新及复制arp数据*/
void copy_arp_data(struct arp_info *dst, struct arp_info *src)
{
	dst->in_ip = src->in_ip;
	dst->host_status = src->host_status;
	strncpy(dst->mac_addr, src->mac_addr, sizeof(dst->mac_addr));		
	strncpy(dst->device,  src->device, sizeof(dst->device));
	strncpy(dst->os_type,  src->os_type, sizeof(dst->os_type));
	strncpy(dst->host_description, src->host_description, sizeof(dst->host_description));
	return ;
}


/*更新及复制host数据*/
void copy_host_data(struct     host_service_info *dst, struct host_service_info *src)
{
	dst->status = src->status;
	dst->port = src->port;
	strncpy(dst->protocol_type, src->protocol_type, sizeof(dst->protocol_type));		
	strncpy(dst->name,  src->name, sizeof(dst->name));
	return ;
}

/*获取nmap表节点数*/
int get_nmap_tbl_nums(HASH_NMAP_T *tbl)
{
	return HASH_COUNT(tbl);
}

/*获取host表节点数*/
int get_host_tbl_nums(HASH_HOST_T *tbl)
{
	return HASH_COUNT(tbl);
}


/*在nmap表添加节点*/
int add_node_to_nmap_table(struct arp_info arp, HASH_NMAP_T **tbl)
{
	HASH_NMAP_T *P = NULL;

	int num = get_nmap_tbl_nums(*tbl);

	if(num > MAX_TBL_NUM)
		return -1;

	P = (struct uthash_nmap *)malloc(sizeof(struct uthash_nmap));
	if(NULL != P)
	{
		copy_arp_data(&P->arp, &arp);
		P->key = arp.in_ip;
		P->header = NULL;
		HASH_ADD_INT(*tbl, key, P);
		return 0;
	}
	return -1;
}

/*在host表添加节点*/
int add_node_to_host_table(struct host_service_info service_info, HASH_HOST_T **tbl)
{
	HASH_HOST_T *P = NULL;

	P = (struct uthash_host *)malloc(sizeof(struct uthash_host));
	if(NULL != P)
	{
		copy_host_data(&P->host_service, &service_info);
		P->key = service_info.port;
		HASH_ADD_INT(*tbl, key, P);
		return 0;
	}
	return 1;
}

/*根据key获取nmap表节点*/
HASH_NMAP_T *find_nmap_node_by_key(unsigned int key, HASH_NMAP_T *tbl)
{
	HASH_NMAP_T *P = NULL;
	HASH_FIND_INT(tbl, &key, P);
	return P;
}

/*根据key获取host表节点*/
HASH_HOST_T *find_host_node_by_key(int key, HASH_HOST_T *tbl)
{
	HASH_HOST_T *P = NULL;
	HASH_FIND_INT(tbl, &key, P);
	return P;
}


/*销毁host表*/
void destroy_host_table(HASH_HOST_T **tbl)
{
	HASH_HOST_T *P1 = NULL, *P2 = NULL;
	HASH_ITER(hh, *tbl, P1, P2){
		HASH_DEL(*tbl, P1);		
		free(P1);
		P1 = NULL;
	}
}

/*销毁链表*/
void destroy_table(HASH_NMAP_T **tbl)
{
	HASH_NMAP_T *P1 = NULL, *P2 = NULL;

	HASH_ITER(hh, *tbl, P1, P2){
		destroy_host_table(&P1->header);
		HASH_DEL(*tbl, P1);
		free(P1);
		P1 = NULL;
	}
}

/*删除nmap表节点*/
int delete_nmap_tbl_node(unsigned int key, HASH_NMAP_T **tbl)
{
	HASH_NMAP_T *P = NULL;

	P = find_nmap_node_by_key(key, *tbl);
	if( NULL != P)
	{
		destroy_host_table(&P->header);
		HASH_DEL(*tbl, P);
		free(P);
		P = NULL;
		return 0;
	}
	return -1;
	
}

/*删除host表节点*/
int delete_host_tbl_node(int key, HASH_HOST_T **tbl)
{
	HASH_HOST_T *P = NULL;

	P = find_host_node_by_key(key, *tbl);
	if( NULL != P)
	{
		HASH_DEL(*tbl, P);
		free(P);
		P = NULL;
		return 0;
	}
	return -1;
}

/*更新nmap表节点信息*/
void update_nmap_tbl_info(struct arp_info arp, HASH_NMAP_T *P)
{
	copy_arp_data(&P->arp, &arp);
}

/*更新host表节点信息*/
void update_host_tbl_info(struct host_service_info service_info, HASH_HOST_T *P)
{
	copy_host_data(&P->host_service, &service_info);
}

void dump_host_tbl_data(HASH_HOST_T *tbl)
{
	HASH_HOST_T *H1 = NULL, *H2 = NULL;

	log_debug("host service num: %d\n", get_host_tbl_nums(tbl));
	HASH_ITER(hh, tbl, H1, H2){
		log_debug("===service_name = %s, port = %d, protocol = %s, status = %d===\n",
			H1->host_service.name, H1->host_service.port, H1->host_service.protocol_type, H1->host_service.status);
	}
}

/*打印表所有数据*/
void dump_tbl_data(HASH_NMAP_T *tbl)
{
	HASH_NMAP_T *N1 = NULL, *N2 = NULL;
	
	log_debug("nmap host num: %d\n", get_nmap_tbl_nums(tbl));
	HASH_ITER(hh, tbl, N1, N2){
		log_debug("####ipAddr = %s, host_status = %d, macAddr = %s, device = %s, host_description = %s, os_type = %s####\n", 
			int_to_ip(N1->arp.in_ip),  N1->arp.host_status, N1->arp.mac_addr, N1->arp.device, N1->arp.host_description, N1->arp.os_type);
		dump_host_tbl_data(N1->header);
		log_debug("################################################################################\n\n");
	}
}

int cjson_get_int(cJSON *obj, char *key, int *val)
{
    cJSON *tmp = NULL;

    tmp = cJSON_GetObjectItem(obj, key);
    if(!tmp || tmp->type != cJSON_Number)
    {
        return -1;
    }

    *val = tmp->valueint;

    return 0;
}

int cjson_get_double(cJSON *obj, char *key, double *val)
{
    cJSON *tmp = NULL;

    tmp = cJSON_GetObjectItem(obj, key);
    if(!tmp || tmp->type != cJSON_Number)
    {
        return -1;
    }

    *val = tmp->valuedouble;

    return 0;
}

char *cjson_get_string(cJSON *obj, char *key)
{
    cJSON *tmp = NULL;

    tmp = cJSON_GetObjectItem(obj, key);
    if(!tmp || tmp->type != cJSON_String)
    {
        return NULL;
    }
    
    return tmp->valuestring;
}


