#include "policyWatcher.h"
#include "commonStruct.h"
#include "parse.h"
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include "utility.h" 

extern Global_conf global_conf;
extern char* PolicyBaseData;
extern char* PolicyTrustData;
extern char* PolicyBlockData;

char macIp[IP_LENGTH] = "";
char injectIp[IP_LENGTH] = "";
char injectMask[IP_LENGTH] = "";
char interfaceIp[IP_LENGTH] = "";
int globalOutLimit = 0;
//char clusterInfo[512][512] = {""};

void parse_sys_conf(const char* data, size_t dataLen)
{
	traceEvent("Parser sys conf begin","get sys conf completed","INFO");

	cJSON* pJson = cJSON_Parse(data);
	if(!pJson){
		traceEvent("Can not parse sys conf","","WARN");
		return;
	}
	cJSON* cSys = cJSON_GetObjectItem(pJson,"sys");
	cJSON* cLogLevel = cJSON_GetObjectItem(cSys,"log_level");
	cJSON* cLogTimer = cJSON_GetObjectItem(cSys,"log_timer");
	cJSON* cEnable = cJSON_GetObjectItem(cSys,"enable");
	if(NULL!=cLogLevel && NULL!=cLogTimer){
		global_conf.sys_conf.log_level = cLogLevel->valueint;
		global_conf.sys_conf.log_timer= cLogTimer->valueint;
		//gpj:todo global_conf.sys_conf.enable = cLogTimer->valueint;
	}else{
		traceEvent("Get json object log_level or log_timer failed","","WARN");
	}
	//OutPutSys2File(true);

}
#if 0
void OutPutSys2File()
{
	Sys_conf* node = &global_conf.sys_conf;
	FILE* fp = fopen("/tmp/output","a+");
	char msg[1024];
	int msgLen = 1024;
	int msgPos = 0;
	int lenTmp = 0;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"addSys{\nlog_level=%d,\n",node->log_level);
	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"log_timer=%d\n",node->log_timer);
    msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"}\n\n");
	fprintf(stderr,"%s",msg);
	fflush(stderr);
	fprintf(fp,"%s",msg);
	fflush(fp);
	fclose(fp);
}

void OutPutBase2File(const char* domainName,Domain_node* node ,bool add_del_flag)
{
	FILE* fp = fopen("/tmp/output","a+");
	char msg[1024];
	int msgLen = 1024;
	int msgPos = 0;
	int lenTmp = 0;
	if(add_del_flag){
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"addBase{\ndomain=\"%s\",\n",domainName);
	}else{
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"delBase{\ndomain=\"%s\",\n",domainName);
	}
	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"cc_level=\"%s\",\n",node->cc_level);
	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"threshold_url=%d,\n",node->threshold_url);
	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"threshold_srcip=%d\n",node->threshold_srcip);
    msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"}\n\n");
	fprintf(stderr,"%s",msg);
	fflush(stderr);
	fprintf(fp,"%s",msg);
	fflush(fp);
	fclose(fp);
}

void OutPutDelDomain2File(const char* domainName)
{
	FILE* fp = fopen("/tmp/output","a+");
	char msg[1024];
	int msgLen = 1024;
	int msgPos = 0;
	int lenTmp = 0;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"delDomain{\ndomain=\"%s\"\n",domainName);
	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"}\n\n");
	fprintf(stderr,"%s",msg);
	fflush(stderr);
	fprintf(fp,"%s",msg);
	fflush(fp);
	fclose(fp);
}


void OutPutQos2File(const char* domainName,Qos_node* node,bool add_del_flag)
{
	/*
	 * add_del_flag:is add or del
	 */
	FILE* fp = fopen("/tmp/output","a+");
	char msg[1024];
	int msgLen = 1024;
	int msgPos = 0;
	int lenTmp = 0;
	if(add_del_flag){
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"addQos{\ndomain=\"%s\",\n",domainName);
	}else{
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"delQos{\ndomain=\"%s\",\n",domainName);
	}
	msgPos = msgPos + lenTmp;
	if(node->https)
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"https=true,\n");
	else
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"https=false,\n");

	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"srcip=\"%s\",\n",node->srcip);
	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"url=\"%s\",\n",node->url);
	msgPos = msgPos + lenTmp;
	if(node->each_srcip)
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"each_srcip=true,\n");
	else
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"each_srcip=false,\n");
	msgPos = msgPos + lenTmp;
	if(node->each_url)
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"each_url=true,\n");
	else
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"each_url=false,\n");
	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"speed=%d\n",node->speed);
	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"}\n\n");
	fprintf(stderr,"%s",msg);
	fflush(stderr);
	fprintf(fp,"%s",msg);
	fflush(fp);
	fclose(fp);

}

void OutPutTrust2File(const char* domainName,Trust_block_table* node,bool add_del_flag)
{
	FILE* fp = fopen("/tmp/output","a+");
	char msg[1024];
	int msgLen = 1024;
	int msgPos = 0;
	int lenTmp = 0;
	if(add_del_flag){
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"addTrust{\ndomain=\"%s\",\n",domainName);
	}else{
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"delTrust{\ndomain=\"%s\",\n",domainName);
	}

	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"srcip=\"%s\",\n",node->srcip);
	fprintf(stderr,"***********************srcip=\"%s\",",node->srcip);
	fflush(stderr);
	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"url=\"%s\"\n",node->url);
    msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"}\n\n");
	fprintf(stderr,"%s",msg);
	fflush(stderr);
	fprintf(fp,"%s",msg);
	fflush(fp);
	close(fp);
}
void OutPutBlock2File(const char* domainName,Trust_block_table* node,bool add_del_flag)
{
	FILE* fp = fopen("/tmp/output","a+");
	char msg[1024];
	int msgLen = 1024;
	int msgPos = 0;
	int lenTmp = 0;
	if(add_del_flag){
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"addBlock{\ndomain=\"%s\",\n",domainName);
	}else{
		lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"delBlock{\ndomain=\"%s\",\n",domainName);
	}

	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"srcip=\"%s\",\n",node->srcip);
	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"url=\"%s\"\n",node->url);
    msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"}\n\n");
	fprintf(stderr,"%s",msg);
	fflush(stderr);
	fprintf(fp,"%s",msg);
	fflush(fp);
	close(fp);
}
#endif 

int parse_policy_base_conf(const char* domainName,Domain_node* dnodePtr)
{
	traceEvent("Do parse policy base conf",domainName,"INFO");
	cJSON* pJson = cJSON_Parse(PolicyBaseData);
//	fprintf(stderr,"policybasedata:%s\n",PolicyBaseData);
//	fflush(stderr);
	if(!pJson)
	  {
		  traceEvent("Parse base conf for json failed,",domainName,"WARN");
		  return -1;
	  }
	strcpy(dnodePtr->domainName,domainName);
	cJSON* pLevel = cJSON_GetObjectItem(pJson,"protect_level");
	if(pLevel)
		strcpy(dnodePtr->cc_level,pLevel->valuestring);

	cJSON* pTsrcip = cJSON_GetObjectItem(pJson,"threshold_srcip");
	dnodePtr->threshold_srcip = pTsrcip->valueint;

	cJSON* pTurl = cJSON_GetObjectItem(pJson,"threshold_url");
	dnodePtr->threshold_url = pTurl->valueint;
	cJSON* pEnable = cJSON_GetObjectItem(pJson,"enable");
//gpj:todo 	dnodePtr->enable = pEnable->valueint;
	//OutPutBase2File(domainName,dnodePtr,true);

//	fprintf(stderr,"get base level:%s,tsrcip:%d,turl:%d\n",dnodePtr->cc_level,dnodePtr->threshold_srcip,dnodePtr->threshold_url);
//	fflush(stderr);

	cJSON* pQos = cJSON_GetObjectItem(pJson,"qos");
	if(!pQos){
		traceEvent("Domain has no qos policy",domainName,"INFO");
        return 0;
	}
	cJSON* pQosPolicy = cJSON_GetObjectItem(pQos,"policy");
	if(!pQosPolicy){
		traceEvent("Domain has no qos policy",domainName,"INFO");
        return 0;
	}
	int cnt = cJSON_GetArraySize(pQosPolicy);
	int i=0;
	for(i=0;i<cnt;i++){
		Qos_node* new_node = malloc(sizeof(Qos_node));

		if(new_node){
			//place node in list
			if(NULL==dnodePtr->qos_list_cur){
				dnodePtr->qos_list_cur = new_node;
				dnodePtr->qos_list = new_node;
			}else{
				//not first node
				dnodePtr->qos_list_cur->next = new_node;
				dnodePtr->qos_list_cur = new_node;
			}
			//write conf to this node
			cJSON* pQosArrayItem = cJSON_GetArrayItem(pQosPolicy,i);
			cJSON* phttps = cJSON_GetObjectItem(pQosArrayItem,"https");
			if(phttps && phttps->type == cJSON_True){
				new_node->https = true;
			}else{
				new_node->https = false;
			}
			cJSON* pSrcip = cJSON_GetObjectItem(pQosArrayItem,"srcip");
			strcpy(new_node->srcip,pSrcip->valuestring);

			cJSON* pUrl = cJSON_GetObjectItem(pQosArrayItem,"url");
			strcpy(new_node->url,pUrl->valuestring);

			cJSON* pEachSrcIp = cJSON_GetObjectItem(pQosArrayItem,"each_srcip");
			if(pEachSrcIp && pEachSrcIp->type == cJSON_True){
				new_node->each_srcip = true;
			}else{
				new_node->each_srcip = false;
			}

			cJSON* pEachUrl = cJSON_GetObjectItem(pQosArrayItem,"each_url");
			if(pEachUrl && pEachUrl->type == cJSON_True){
				new_node->each_url = true;
			}else{
				new_node->each_url = false;
			}

			cJSON* pSpeed = cJSON_GetObjectItem(pQosArrayItem,"value");
		//	fprintf(stderr,"QQQQQQQQQos domain:%s,value:%d,  %d",domainName,new_node->speed,pSpeed->valueint);
			new_node->speed = pSpeed->valueint;

	//		OutPutQos2File(domainName,new_node,true);

		}

	}
    return 0;
}

void parse_policy_trust_list(const char* domainName,Domain_node* dnodePtr)
{
	traceEvent("Do parse policy trust list",domainName,"INFO");
	if(strlen(PolicyTrustData)<10){
		traceEvent("Has no trust list ",domainName,"INFO");
	}
	cJSON* pJson = cJSON_Parse(PolicyTrustData);
	fprintf(stderr,"policytrustdata:%s\n",PolicyTrustData);
	fflush(stderr);
	if(!pJson)
	  {
		  traceEvent("Parse trust conf for json failed,",domainName,"WARN");
		  return ;
	  }

	cJSON* pTrustList = cJSON_GetObjectItem(pJson,"trust_list");
	if(!pTrustList){
		traceEvent("Domain has no trust list ",domainName,"INFO");
        return ;
	}
	int cnt = cJSON_GetArraySize(pTrustList);
	int i=0;
	for(i=0;i<cnt;i++){
		Trust_block_table* new_node = malloc(sizeof(Trust_block_table));
		if(new_node){
			//place node in list
			if(dnodePtr->trust_list_cur){
				//not first node
				dnodePtr->trust_list_cur->next = new_node;
				dnodePtr->trust_list_cur = new_node;

			}else{
				dnodePtr->trust_list_cur = new_node;
				dnodePtr->trust_list = new_node;
			}
			//write conf to this node
			cJSON* pTrustArrayItem = cJSON_GetArrayItem(pTrustList,i);
			cJSON* pSrcip = cJSON_GetObjectItem(pTrustArrayItem,"srcip");
			strcpy(new_node->srcip,pSrcip->valuestring);
//			fprintf(stderr,"get---------srcip:%s,new_node:srcip:%s\n",pSrcip->valuestring,new_node->srcip);
//			fflush(stderr);

			cJSON* pUrl = cJSON_GetObjectItem(pTrustArrayItem,"url");
			strcpy(new_node->url,pUrl->valuestring);

//			OutPutTrust2File(domainName,new_node,true);

		}else{
			traceEvent("Malloc failed in parse trust list",domainName,"WARN");
		}
	}
}
void parse_policy_block_list(const char* domainName,Domain_node* dnodePtr)
{
	traceEvent("Do parse policy block list",domainName,"INFO");
	if(strlen(PolicyBlockData)<10){
		traceEvent("Has no block list ",domainName,"INFO");
	}
	cJSON* pJson = cJSON_Parse(PolicyBlockData);
//	fprintf(stderr,"policytrustdata:%s\n",PolicyBlockData);
//	fflush(stderr);
	if(!pJson)
	  {
		  traceEvent("Parse block conf for json failed,",domainName,"WARN");
		  return ;
	  }

	cJSON* pBlockList = cJSON_GetObjectItem(pJson,"block_list");
	if(!pBlockList){
		traceEvent("Domain has no block list ",domainName,"INFO");
        return ;
	}
	int cnt = cJSON_GetArraySize(pBlockList);
	int i=0;
	for(i=0;i<cnt;i++){
		Trust_block_table* new_node = malloc(sizeof(Trust_block_table));
		if(new_node){
			//place node in list
			if(NULL==dnodePtr->block_list_cur){
				dnodePtr->block_list_cur = new_node;
				dnodePtr->block_list = new_node;
			}else{
				//not first node
				dnodePtr->block_list_cur->next = new_node;
				dnodePtr->block_list_cur = new_node;
			}
			//write conf to this node
			cJSON* pBlockArrayItem = cJSON_GetArrayItem(pBlockList,i);
			cJSON* pSrcip = cJSON_GetObjectItem(pBlockArrayItem,"srcip");
			strcpy(new_node->srcip,pSrcip->valuestring);

			cJSON* pUrl = cJSON_GetObjectItem(pBlockArrayItem,"url");
			strcpy(new_node->url,pUrl->valuestring);

//			OutPutBlock2File(domainName,new_node,true);

		}
	}
}


