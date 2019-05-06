
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/un.h> 
#include <pthread.h>

#include "cjson.h"
#include "utils.h"
#include "config.h"

int g_scan_rate_time = SCAN_EATE_TIME;
int g_check_status_time = 0;
int daemon_flag = 1;
int debug_flag = 0;
pthread_mutex_t mutex;

void free_all_data()
{
	int i = 0;

	for(i = 0; i < MAX_LAN_NUM; i ++)
		destroy_table(&lan_table[i]);
}

void dump_all_data()
{
	int i = 0;

	for(i = 0; i < MAX_LAN_NUM; i ++)
		dump_tbl_data(lan_table[i]);
}

void process_exit()
{
	free_all_data();	
	pthread_mutex_destroy(&mutex);
	exit(0);
}

void show_use(const char *target)
{
	fprintf(stderr, "%s\n"
			"	-f, close daemon\n"
			"	-D, open debug info\n"
			"	-h, print this help\n",
			target);
}

void handle_paramter(int argc, char *argv[])
{
	int ch;

	while( (ch = getopt(argc, argv, "fDh")) != -1 )
	{
		switch(ch)
		{
			case 'f':
				daemon_flag = 0;
				break;
			case 'D':
				debug_flag = 1;
				break;
			case 'h':
				show_use(argv[0]);
				exit(1);
		}
	}
	return ;
}

void sig_handler(int signo)
{
	//log_debug("signo = %d\n", signo);
	switch(signo)
	{
		case SIGINT:
		case SIGTERM:
			process_exit();
			break;
		default:
			return;
	}
}

void init_sigaction()
{
	struct sigaction act;

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = sig_handler;

	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);	
	return ;
}

void init_global()
{
	int i = 0;
	for(i = 0; i < MAX_LAN_NUM; i++)
	{
		lan_table[i] = NULL;
		memset(&ip_table[i], 0x0, sizeof(ip_table[i]));
		ip_table[i].idx = -1;
	}

	load_config(&g_nmap_config);
	if(g_nmap_config.scan_rate == 0)
		g_nmap_config.scan_rate = SCAN_EATE_TIME;
	
	if(g_nmap_config.scan_depth == 0)
		g_nmap_config.scan_depth = DEFAULT_SCAN_DEPTH;
	
	g_scan_rate_time = g_nmap_config.scan_rate;   
}

int init_unix_server(const char *path)
{
	int ret = 0, sockfd = 0;
	struct sockaddr_un addr;

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sockfd < 0)
	{
		log_error("socket:%s\n", strerror(errno));
		return -1;
	}

	memset(&addr, 0x0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	unlink(path);

	ret = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
	if(ret < 0)
	{
		log_error("bind:%s\n", strerror(errno));
		close(sockfd);
		return -1;
	}

	ret = listen(sockfd, UNIX_LISTEN_NUMS);
	if(ret < 0)
	{
		log_error("listen:%s\n", strerror(errno));
		close(sockfd);
		return -1;
	}

	return sockfd;
}

void burs_service_packet(HASH_HOST_T *tbl, cJSON *obj)
{
	HASH_HOST_T *H1 = NULL, *H2 = NULL;

	cJSON *arr = cJSON_CreateArray();
	if(NULL == arr)
	{
		log_error("create arr failed\n");
		return ;
	}

	HASH_ITER(hh, tbl, H1, H2){	
		cJSON *subObj = cJSON_CreateObject();
		if(subObj)
		{
			cJSON_AddNumberToObject(subObj, "port", H1->host_service.port);
			cJSON_AddStringToObject(subObj, "protocol", H1->host_service.protocol_type);
			cJSON_AddStringToObject(subObj, "name", H1->host_service.name);
			cJSON_AddNumberToObject(subObj, "status", H1->host_service.status);

			cJSON_AddItemToArray(arr, subObj);
		}
	}

	cJSON_AddItemToObject(obj, "service", arr);
	return ;
}

void get_nmap_data(cJSON *root)
{
	int i = 0;
	int ret = 0;
	int code = 0;
	cJSON *arr = NULL, *item = NULL;
	HASH_NMAP_T *P1 = NULL, *P2 = NULL;
	
	item = cJSON_CreateObject();
	arr = cJSON_CreateArray();
	if( NULL == item || NULL == arr)
	{
		log_error("create json obj failed!\n");
		return;
	}
		
	pthread_mutex_lock(&mutex);
	for(i = 0; i < MAX_LAN_NUM; i ++)
	{
		cJSON *subArr = NULL;
		if(lan_table[i]== NULL)
			continue;
		
		subArr = cJSON_CreateArray();
		if(NULL == subArr)
		{
			log_error("create arr failed\n");
			pthread_mutex_unlock(&mutex);
			return;
		}

		HASH_ITER(hh, lan_table[i], P1, P2){
			log_debug("ip = %s, num = %d\n", int_to_ip(P1->arp.in_ip), get_host_tbl_nums(P1->header));
			// 将没有扫描到服务的主机过滤掉，不上传到应用层
			if(P1->header != NULL)
			{
				cJSON *subObj = cJSON_CreateObject();
				if(subObj)
				{ 
					cJSON_AddStringToObject(subObj, "ip", int_to_ip(P1->arp.in_ip));
					cJSON_AddStringToObject(subObj, "mac", P1->arp.mac_addr);
					cJSON_AddStringToObject(subObj, "description", P1->arp.host_description);
					cJSON_AddNumberToObject(subObj, "host_status", P1->arp.host_status);
					cJSON_AddStringToObject(subObj, "os_type", P1->arp.os_type);
					burs_service_packet(P1->header, subObj);
					cJSON_AddItemToArray(subArr, subObj);
				}
			}
		}
		cJSON_AddItemToObject(item, lan_table[i]->arp.device, subArr);
	}	
	pthread_mutex_unlock(&mutex);
	
	cJSON_AddItemToArray(arr, item);
	cJSON_AddNumberToObject(root, "code", code);	
	cJSON_AddItemToObject(root, "data", arr);
}

void sendto_nmap_data(int sockfd)
{
	int ret = 0;
	int datalen = 0;
	char *data = NULL;
	cJSON *root = NULL;
	
	root = cJSON_CreateObject();
	if(!root)
	{
		log_error("create json obj failed!\n");
		return;
	}
	get_nmap_data(root);

	data = cJSON_PrintUnformatted(root);
	if(!data)
	{
		log_error("print unformatted json failed!\n");
		goto end_proc;
	}
	datalen = strlen(data);
	
	ret = send(sockfd, data, datalen, MSG_NOSIGNAL);
	if(ret < 0 || ret != datalen)
	{
		log_error("send error!\n");
		goto end_proc;
	}
	log_debug("send:>> [%d][#%s#]\n", datalen, data);
	
end_proc:
	if(root)
	{
		cJSON_Delete(root);
	}
	if(data) 
	{
		free(data);
	}
	return ;
}

void handle_uncfd_packet(int sockfd)
{
	int ret = 0;
	char recvbuf[1024] = {0};
	cJSON *rObj = NULL, *data = NULL;
	char *cmd = NULL;

	ret = recv(sockfd, recvbuf, sizeof(recvbuf), 0);
	if(ret < 0)
	{
		log_error("recv:%s\n", strerror(errno));
		return ;
	}
	else if(ret == 0)
	{
		log_error("peer close \n");
		return ;
	}
	
    rObj = cJSON_Parse(recvbuf);
    if(rObj == NULL)
    {
        log_error("parse json error\n");
        return;
    }
	
    cmd = cjson_get_string(rObj, "cmd");
    if(!cmd)
    {
        log_error("param error!\n");
        goto error;
    }

	log_debug("cmd===%s\n", cmd);
	if(strcmp(cmd, "get_nmap_data") == 0)
	{
		sendto_nmap_data(sockfd);
	}

	data = cJSON_GetObjectItem(rObj, "data");
	if(data)
	{
		//根据data在解析数据
	}
	
error:
    if(rObj)
    {
        cJSON_Delete(rObj);
    }
	return ;
}
//========================================================================================
int get_nmap_scan_cmd(char *cmdbuf, int cmdlen)
{
	int ret = 0;

	/*必要参数*/
	ret += snprintf(cmdbuf, cmdlen - ret, "nmap -T4");
	/*可选参数*/
	if(g_nmap_config.port_pool[0] != '\0')
		ret += snprintf(cmdbuf+ret, cmdlen - ret, " -p%s", g_nmap_config.port_pool);
	if(g_nmap_config.timeout != 0)
		ret += snprintf(cmdbuf+ret, cmdlen - ret, " --host-timeout %ds", g_nmap_config.timeout);
	if(g_nmap_config.retry_count != 0)
		ret += snprintf(cmdbuf+ret, cmdlen - ret, " --max-retries %d", g_nmap_config.retry_count);

	return ret;
}

int get_host_dev_type(FILE *fp, struct arp_info *arp)
{
	int len = 0;
	char strline[1024] = {0};
	char buf[64] = {0};

	memset(strline, 0x0, sizeof(strline));

	fseek(fp, 0L, SEEK_SET);
	while(fgets(strline, sizeof(strline), fp))
	{
		if(strstr(strline, "Host seems down"))
			return -1;
		
		if(strstr(strline, "MAC Address: "))
		{
			len = strlen(strline);
			strline[len - 2] = '\0';
			snprintf(arp->host_description, sizeof(arp->host_description), "%s", strstr(strline, "(") + 1);
			return 0;
		}
	}
	return 0;
}

int find_char_pos(const char *str, int len, char ch)
{
	int i = 0, pos = 0;

	for(i = 0; i < len; i++)
	{
		if(str[i] == ch)
		{
			pos = i;
			break;
		}
	}
	return pos;
}

int find_keyvalue_to_str(FILE *fp, const char *key, char *os_type, int size)
{	
	char strline[1024] = {0};
	int startPos = 0, endPos = 0;
	int len = 0, find = 0;
	char *tmp = NULL;

	fseek(fp, 0L, SEEK_SET);
	while(fgets(strline, sizeof(strline), fp))
	{	
		if(strstr(strline, key))
		{
			len = strlen(strline);
			strline[len - 1] = '\0';
					
			startPos = find_char_pos(strline, len, ':') + 2;
			tmp = strline + startPos;

			len = strlen(tmp);
			endPos = find_char_pos(tmp, len, '(') - 1;
			if(endPos != 0)
				strline[startPos + endPos] = '\0';
			
			snprintf(os_type, size, "%s", strline + startPos);
			find = 1;
			break;
		}
	}

	return find;
}


int get_host_os_type(FILE *fp, struct arp_info *arp)
{
	if(find_keyvalue_to_str(fp, "OS details: ", arp->os_type, sizeof(arp->os_type)) == 0)
		if(find_keyvalue_to_str(fp, "Running", arp->os_type, sizeof(arp->os_type)) == 0)
			find_keyvalue_to_str(fp, "Aggressive OS guesses:", arp->os_type, sizeof(arp->os_type));
	return 0;
}

void get_service_info(FILE *fp, HASH_HOST_T **tbl)
{
	char strline[1024] = {0};

	memset(strline, 0x0, sizeof(strline));

	fseek(fp, 0L, SEEK_SET);
	while(fgets(strline, sizeof(strline), fp))
	{	
		int matchs = 0,  port = 0;
		char protocol_type[10] = {0}, status[20] = {0}, server_name[20] = {0} ;
		struct host_service_info host_service;
		HASH_HOST_T *P = NULL;

		memset(&host_service, 0x0, sizeof(struct host_service_info));
		matchs = sscanf(strline, "%d/%s %s %s", &port, protocol_type, status, server_name);
		if(matchs != 4)
		{	
			continue;
		}
		
		/*
		 * 根据port判断该服务在对应主机是否存在
		 * 如果存在就更新信息，不存在就添加到链表
		*/
		host_service.port = port;
		if(!strncmp(status, "open", 4))
			host_service.status = 1;
		else
			host_service.status = 0;
		
		strncpy(host_service.name, server_name, sizeof(host_service.name));
		strncpy(host_service.protocol_type, protocol_type, sizeof(host_service.protocol_type));

		P = find_host_node_by_key(port, *tbl);
		if( NULL != P)
			update_host_tbl_info(host_service, P);
		else
			add_node_to_host_table(host_service, tbl);
		
		//log_debug("arp: port = %d, protocol_type = %s, status  = %s, server_name = %s\n", 
		//	port, protocol_type, status, server_name);
	}
	return ;
}

void update_and_add_data_to_table(struct arp_info arp, HASH_NMAP_T **tbl)
{
	HASH_NMAP_T *P = NULL;
	
	P = find_nmap_node_by_key(arp.in_ip, *tbl);
	if(NULL != P)
	{
		update_nmap_tbl_info(arp, P);
	}
	else
	{
		add_node_to_nmap_table(arp, tbl);
	}	
}


void get_host_all_info(struct arp_info arp, int lan_port)
{
	HASH_NMAP_T *P1 = NULL, *P2 = NULL;
	FILE *fp = NULL;

	fp = fopen(TMP_NMAP_FILE, "r");
	if(!fp)
	{
		log_error("fopen:%s error(%s)\n", TMP_NMAP_FILE, strerror(errno));
		return ;
	}

	if(get_host_dev_type(fp, &arp) < 0)
		goto cleanup;
	
	get_host_os_type(fp, &arp);
	log_debug("ip:%s, macAddr:%s, os_type:%s, desc:%s, device:%s\n", 
		int_to_ip(arp.in_ip), arp.mac_addr, arp.os_type, arp.host_description, arp.device);
	arp.host_status = 1;
	
	pthread_mutex_lock(&mutex);
	/* 将host基本信息插入链表或者更新信息 */
	update_and_add_data_to_table(arp, &lan_table[lan_port]);

	/* 获取主机对应的服务信息 */
	HASH_ITER(hh, lan_table[lan_port], P1, P2){
		if(P1->arp.in_ip == arp.in_ip)
			get_service_info(fp, &P1->header);
	}
	pthread_mutex_unlock(&mutex);
cleanup:
	fclose(fp);
	return ;
}

/*根据traceroute获取主机跃点数*/
int get_host_metric(const char *ipAddr)
{
	FILE *fp = NULL;
	int metric = 0, find = 0;
	char cmdbuf[1024] = {0}, strline[1024] = {0};

	memset(cmdbuf, 0x0, sizeof(cmdbuf));
	memset(strline, 0x0, sizeof(strline));
	snprintf(cmdbuf, sizeof(cmdbuf), "nmap -sn --traceroute %s", ipAddr);

	log_debug("cmdbuf = %s\n", cmdbuf);
	fp = popen(cmdbuf, "r");
	if(fp != NULL)
	{
		while(fgets(strline, sizeof(strline), fp))
		{
			if(strstr(strline, "TRACEROUTE"))
				find = 1;
			
			if(find == 1)
			{
				if(strstr(strline, ipAddr))
				{
					metric = strline[0] - '0';
					break;
				}
			}
		}
		pclose(fp);
	}
	
	return metric;
}

/* 根据主机地址扫描获取对应的服务信息 */
void get_host_service_info_by_ip(const char *ipAddr, const char *macAddr, int lan_port)
{	
	int ret = 0, metric = 0;
	char cmdbuf[1024] = {0};

	struct arp_info arp;
	memset(&arp, 0x0, sizeof(struct arp_info));
	memset(cmdbuf, 0x0, sizeof(cmdbuf));

	metric = get_host_metric(ipAddr);
	log_debug("metric == %d\n", metric);
	if(metric == 0 || metric > g_nmap_config.scan_depth)
	{
		log_debug("scan depth is not ok!\n");
		return ;
	}
	
	/*获取扫描命令参数*/
	ret = get_nmap_scan_cmd(cmdbuf, sizeof(cmdbuf));
	snprintf(cmdbuf+ret, sizeof(cmdbuf) - ret, " -O --fuzzy --osscan-guess %s > %s", ipAddr, TMP_NMAP_FILE);
	system(cmdbuf);

	log_debug("cmdbuf = %s\n", cmdbuf);
	
	arp.in_ip = inet_addr(ipAddr);
	arp.host_status = 0;
	strncpy(arp.mac_addr, macAddr, sizeof(arp.mac_addr));
	strncpy(arp.device, get_lan_name(lan_port), sizeof(arp.device));
	strncpy(arp.os_type, "unknown", sizeof(arp.os_type));
	strncpy(arp.host_description, "unknown", sizeof(arp.host_description));

	get_host_all_info(arp, lan_port);
	
	unlink(TMP_NMAP_FILE);
}

void read_proc_net_arp()
{
	FILE *fp = NULL;
	int hwType = 0, flags = 0;
	char ipAddr[16] = {0}, macAddr[18] = {0}, mask[10] = {0}, device[20] = {0}, description[64] = {0};
	char strline[1024] = {0};

	fp = fopen(PROC_NET_ARP, "r");
	if(NULL == fp)
	{
		log_error("fopen %s failed(%s)\n", PROC_NET_ARP, strerror(errno));
		return ;
	}

	while(fgets(strline, sizeof(strline), fp))
	{
		int matchs = 0, lan_port = 0;
		
		matchs = sscanf(strline, "%s %x %x %s %s %s", ipAddr, &hwType, &flags, macAddr, mask, device);
		lan_port = get_lan_idx(device);

		if(matchs != 6 || lan_port < 0)
			continue;

		/* 根据主机地址扫描获取对应的服务信息 */
		get_host_service_info_by_ip(ipAddr, macAddr, lan_port);
	}

	fclose(fp);
	return ;
}


/*检测服务状态*/
int check_server_status(unsigned int inIp, int port, int *s_status)
{
	FILE *fp = NULL;
	char cmdbuf[64] = {0}, strline[1024] = {0};
	
	memset(cmdbuf, 0x0, sizeof(cmdbuf));
	memset(strline, 0x0, sizeof(strline));
	snprintf(cmdbuf, sizeof(cmdbuf), NMAP_CMD_FORMAT, int_to_ip(inIp), port);

	fp = popen(cmdbuf, "r");
	if(NULL == fp)
	{
		log_error("popen %s failed(%s)\n", cmdbuf, strerror(errno));
		return 0;
	}
	log_debug("cmdbuf = %s\n", cmdbuf);

	while(fgets(strline, sizeof(strline), fp))
	{	
		int matchs = 0,  port = 0;
		char protocol_type[10] = {0}, status[20] = {0}, server_name[20] = {0};

		if(strstr(strline, "(0 hosts up)"))
		{
			*s_status = 0;
			pclose(fp);
			return 0;
		}

		matchs = sscanf(strline, "%d/%s %s %s", &port, protocol_type, status, server_name);
		if(matchs != 4)
			continue;
		
		log_debug("service: ip_addr = %s, port = %d, protocol_type = %s, status  = %s, server_name = %s\n", 
			int_to_ip(inIp), port, protocol_type, status, server_name);
		if(!strncmp(status, "open", 4))
			*s_status = 1;
		else
			*s_status = 0;
		break;
	}
	
	pclose(fp);
	return 1;
}

/*扫描所有主机服务状态*/
void scan_all_host_service_status()
{
	int i = 0;
	HASH_NMAP_T *P1 = NULL, *P2 = NULL;
	HASH_HOST_T *H1 = NULL, *H2 = NULL;
	
	for(i = 0; i < MAX_LAN_NUM; i++)
	{
		HASH_ITER(hh, lan_table[i], P1, P2){
			if(P1->header == NULL || 
				!strncmp(P1->arp.host_description, "unknown", 7) ||
				!strncmp(P1->arp.os_type, "unknown", 7))
			{
				// 主机没有检测到服务或者没有扫到系统类型及设备名称，重新扫描
				get_host_service_info_by_ip(int_to_ip(P1->arp.in_ip), P1->arp.mac_addr, i);
			}
			else
			{
				// 主机检测到对应的服务，检查服务状态
				HASH_ITER(hh, P1->header, H1, H2){
					int s_status = 0, h_status = 0;
					if(P1->arp.host_status == 1)
						h_status = check_server_status(P1->arp.in_ip, H1->host_service.port, &s_status);

					log_debug("s_status = %d, h_status = %d\n", s_status, h_status);
					pthread_mutex_lock(&mutex);
					P1->arp.host_status = h_status;
					H1->host_service.status = s_status;
					pthread_mutex_unlock(&mutex);	
				}
			}
		}
	}	
}

int split_ip_pool(char *ip_pool, const char *split_ch, int max_num)
{
	int i = 0;
	char *token = NULL;

	if(ip_pool[0] != '\0')
	{
		token = strtok(ip_pool, split_ch);
		
		while(token != NULL && max_num)
		{
			ip_table[i].idx = i;
			strncpy(ip_table[i].ipAddr, token, sizeof(ip_table[i].ipAddr));
			token = strtok(NULL, split_ch);
			max_num --;
			i++;
		}
	}
	return 0;
}

/*扫描一个ip池*/
void scan_one_ip_pool_service(struct ip_pool table)
{
	FILE *fp = NULL;
	int find = 0, len = 0, ret = 0;
	char cmdbuf[1024] = {0}, strline[1024] = {0};
	char ipAddr[16] = {0}, macAddr[18] = {0};

	memset(strline, 0x0, sizeof(strline));

	ret += snprintf(cmdbuf, sizeof(cmdbuf), "nmap -T4");
	if(g_nmap_config.process_num != 0)
		ret += snprintf(cmdbuf+ret, sizeof(cmdbuf) - ret, " --min-hostgroup %d", g_nmap_config.process_num);
	snprintf(cmdbuf+ret, sizeof(cmdbuf) - ret, " -sn %s", table.ipAddr);
	log_debug("cmdbuf = %s\n", cmdbuf);

	fp = popen(cmdbuf, "r");
	if(fp != NULL)
	{
		while(fgets(strline, sizeof(strline), fp))
		{
			if(strstr(strline, "Nmap scan report for "))
			{
				len = strlen(strline);
				strline[len-1] = '\0';
				sscanf(strline, "%*[^0-9]%[0-9.]", ipAddr);
			}

			if(strstr(strline, "MAC Address: "))
			{
				len = strlen(strline);
				strline[len-1] = '\0';
				sscanf(strline, "MAC Address: %s", macAddr);
				find = 1;
			}

			if(find == 1)
			{
				log_debug("ipAddr = %s, macAddr = %s, idx = %d\n", ipAddr, macAddr, table.idx);
				get_host_service_info_by_ip(ipAddr, macAddr, table.idx);
				find = 0;
			}
		}
		pclose(fp);
	}
	return ;
}


/* 扫描所有的IP池 */
void scan_all_ip_pool_service()
{
	int i = 0;
	for(i; i < MAX_LAN_NUM; i++)
	{
		log_debug("ip_table[%d].idx = %d, ipaddr = %s\n", i, ip_table[i].idx,ip_table[i].ipAddr);
		if(ip_table[i].idx != -1)
			/*扫描一个ip池*/
			scan_one_ip_pool_service(ip_table[i]);
	}
}

void manual_scan_host_service()
{
	/* 分割IP地址池      */
	split_ip_pool(g_nmap_config.ip_pool, ",", MAX_LAN_NUM);
	/* 扫描所有的IP池 */
	scan_all_ip_pool_service();
}

void auto_scan_host_service()
{
	/* 从ARP表读取主机地址 */
	read_proc_net_arp();
}

void *nmap_scan_host_data(void *ptr)
{	
	int ret = 0;
	struct timeval tv;

	while(1)
	{
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		ret = select(0, NULL, NULL, NULL, &tv);
		
		if(ret < 0)
		{
			if(errno == EINTR)
				continue;
			log_debug("select:%s\n", strerror(errno));
			break;
		}
		
		if(g_scan_rate_time >= g_nmap_config.scan_rate)
		{
			/* 清空链表 */
			//free_all_data();
			if(g_nmap_config.manual == 1)
			{
				log_debug("manual get host ip addr\n");
				/* 扫描设置主机对应的服务 */
				manual_scan_host_service();
			}
			else
			{
				log_debug("auto get host ip addr\n");
				/* 扫描读取arp表主机对应的服务 */
				auto_scan_host_service();
			}		
			dump_all_data();
			g_scan_rate_time = 0;
		}
		
		if(g_check_status_time >= CHECK_STATUS_TIMER)
		{
			/* 检测主机对应服务开启状态 */
			scan_all_host_service_status();
			g_check_status_time = 0;
		}
		
		g_check_status_time++;
		g_scan_rate_time++;
	}
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int unsfd = -1, uncfd = -1, maxfd = 0;
	struct timeval tv;
	fd_set rfds;
	pthread_t pid;

	/*参数处理*/
	handle_paramter(argc, argv);

	log_debug("debug = %d, daemon = %d\n", debug_flag, daemon_flag);
	/*守护进程*/
	if(daemon_flag == 1)
		daemon(0, 1);

	init_global();
	log_debug("manual = %d, rate = %d, retry_count = %d, timeout = %d, ip_pool = %s, port_pool = %s, scan_depth = %d, process_num = %d\n",
			g_nmap_config.manual, g_nmap_config.scan_rate, g_nmap_config.retry_count, g_nmap_config.timeout,
			g_nmap_config.ip_pool, g_nmap_config.port_pool, g_nmap_config.scan_depth, g_nmap_config.process_num);
	
	/*初始化信号量*/
	init_sigaction();
	
	pthread_mutex_init(&mutex, NULL);
	ret = pthread_create(&pid, NULL, nmap_scan_host_data, NULL);
	if(ret != 0)
	{
		log_error("pthread_create:%s\n", strerror(errno));
		return -1;
	}
	
	unsfd = init_unix_server(UNIX_SERVER_PATH);
	if(unsfd < 0)
	{
		log_error("init unix server failed\n");
		return -1;
	}
	maxfd = unsfd;
	
	while(1)
	{		
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_ZERO(&rfds);
		FD_SET(unsfd, &rfds);

		if(uncfd > 0)
			FD_SET(uncfd, &rfds);

		ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
		if(ret < 0)
		{
			if(errno == EINTR)
				continue;
			log_debug("select:%s\n", strerror(errno));
			break;
		}
		
		if(FD_ISSET(unsfd, &rfds))
		{
			uncfd = accept(unsfd, NULL, NULL);
			if(uncfd < 0)
			{
				log_debug("accept:%s\n", strerror(errno));
				continue;
			}

			maxfd = (maxfd < uncfd) ? uncfd : maxfd;
		}

		if(uncfd > 0 && FD_ISSET(uncfd, &rfds))
		{
			handle_uncfd_packet(uncfd);
			FD_CLR(uncfd, &rfds);
			close(uncfd);
			uncfd = -1;
		}
	}
	
	return 0;
}
