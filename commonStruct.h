/*
 * =====================================================================================
 *
 *       Filename:  list_struct.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  11/09/2016 09:45:19 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *        Company:  
 *
 * =====================================================================================
 */
/*************************************************************************
	> File Name: list_struct.h
	> Author: ma6174
	> Mail: ma6174@163.com 
	> Created Time: Wed 09 Nov 2016 09:45:19 PM PST
 ************************************************************************/
#ifndef _LIST_STRUCT_H_
#define _LIST_STRUCT_H_
//gpj
#define DOMAIN_LENGTH                   256
#define S_LENGTH                        8
#define M_LENGTH                        8
#define IP_LENGTH                       16
#define SYS_CONF_PATH                   "/sys"
#define DOMAIN_CONF_PATH                "/policy"
#define TRUST_CONF_PATH                 "/policy_data/trust_list"
#define BLOCK_CONF_PATH                 "/policy_data/block_list"
#define URL_LENGTH                      256

typedef struct sys_conf{
    bool enable;
	int log_level;
	int log_timer;
}Sys_conf;
typedef struct qos_node{
	bool https;
	char srcip[IP_LENGTH];
	char url[URL_LENGTH];
	bool each_srcip;
	bool each_url;
	int  speed;
	struct qos_node* next;
}Qos_node;
typedef struct trust_block_table{
	char srcip[IP_LENGTH];
	char url[URL_LENGTH];
	struct trust_block_table* next;
}Trust_block_table;
typedef struct domain_node{
	char domainName[URL_LENGTH];
	char cc_level[S_LENGTH];
    int threshold_srcip;	
    int threshold_url;	
    bool enable;
	Qos_node* qos_list;
	Qos_node* qos_list_cur;
	Trust_block_table* trust_list;
	Trust_block_table* trust_list_cur;
	Trust_block_table* block_list;
	Trust_block_table* block_list_cur;
    struct domain_node* pre;
    struct domain_node* next;
}Domain_node;

typedef struct global_conf{
	    Sys_conf sys_conf;
	    int domainNum;
        Domain_node* domain_list;
        Domain_node* domain_list_cur;
}Global_conf;

#endif

