#include "policyWatcher.h"
#include "list_struct.h"
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
	if(NULL!=cLogLevel && NULL!=cLogTimer){
		global_conf.sys_conf.log_level = cLogLevel->valueint;
		global_conf.sys_conf.log_timer= cLogTimer->valueint;
	}else{
		traceEvent("Get json object log_level or log_timer failed","","WARN");
	}
	OutPutSys2File(true);

}
void free_qos_list(Qos_node* qos_ptr)
{
	while(qos_ptr)
	{
		Qos_node* node_tmp = qos_ptr;
		qos_ptr = qos_ptr->next;
		free(node_tmp);
	}
}

xmlXPathObjectPtr getNodeset(xmlDocPtr doc, const xmlChar *xpath)  
{  
	xmlXPathContextPtr context;  
	xmlXPathObjectPtr result;  
	context = xmlXPathNewContext(doc);  

	if (context == NULL) {  
		fprintf(stderr,"context is NULL\n");  
		traceEvent("GetNodeset ","context is NULL","WARN");
		return NULL;  
	}  

	result = xmlXPathEvalExpression(xpath, context);  
	xmlXPathFreeContext(context);  
	if (result == NULL) {  
		fprintf(stderr,"xmlXPathEvalExpression return NULL\n");  
		traceEvent("GetNodeset "," xmlXpathEvalExpression return NULL","WARN");
		return NULL;  
	}  

	if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {  
		xmlXPathFreeObject(result);  
		fprintf(stderr,"nodeset is empty\n");  
		traceEvent("GetNodeset "," nodeset is empty","INFO");
		return NULL;  
	}  

	return result;  
}

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
	close(fp);
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
	close(fp);
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
	close(fp);
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
	close(fp);

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


bool parse_policy_base_conf(const char* domainName,Domain_node* dnodePtr)
{
	traceEvent("Do parse policy base conf",domainName,"INFO");
	cJSON* pJson = cJSON_Parse(PolicyBaseData);
	fprintf(stderr,"policybasedata:%s\n",PolicyBaseData);
	fflush(stderr);
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
	OutPutBase2File(domainName,dnodePtr,true);

	fprintf(stderr,"get base level:%s,tsrcip:%d,turl:%d\n",dnodePtr->cc_level,dnodePtr->threshold_srcip,dnodePtr->threshold_url);
	fflush(stderr);

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
			fprintf(stderr,"QQQQQQQQQos domain:%s,value:%d,  %d",domainName,new_node->speed,pSpeed->valueint);
			new_node->speed = pSpeed->valueint;

			OutPutQos2File(domainName,new_node,true);

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
			if(NULL==dnodePtr->trust_list_cur){
				dnodePtr->trust_list_cur = new_node;
				dnodePtr->trust_list = new_node;
			}else{
				//not first node
				dnodePtr->trust_list_cur->next = new_node;
				dnodePtr->trust_list_cur = new_node;
			}
			//write conf to this node
			cJSON* pTrustArrayItem = cJSON_GetArrayItem(pTrustList,i);
			cJSON* pSrcip = cJSON_GetObjectItem(pTrustArrayItem,"srcip");
			strcpy(new_node->srcip,pSrcip->valuestring);
			fprintf(stderr,"get---------srcip:%s,new_node:srcip:%s\n",pSrcip->valuestring,new_node->srcip);
			fflush(stderr);

			cJSON* pUrl = cJSON_GetObjectItem(pTrustArrayItem,"url");
			strcpy(new_node->url,pUrl->valuestring);

			OutPutTrust2File(domainName,new_node,true);

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
	fprintf(stderr,"policytrustdata:%s\n",PolicyBlockData);
	fflush(stderr);
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

			OutPutBlock2File(domainName,new_node,true);

		}
	}
}


void parseDomainPolicy(const char* urlName,size_t nameLen,const char* baseData,size_t baseLen,const char* trustData,size_t trustLen,const char* blockData,size_t blockLen,bool addFlag)
{
	traceEvent("Parser policy","loop parse","INFO");
	//new domain add
	Domain_node* set_domain_ptr = NULL;
	if(false==addFlag){
		Domain_node* domain_ptr = global_conf.domain_list;
        for( ;domain_ptr;domain_ptr=domain_ptr->next){
			if(memcmp(domain_ptr->domainName,urlName,nameLen)==0){
				set_domain_ptr = domain_ptr;
			}
		}
	}

	if(NULL==set_domain_ptr){
	    set_domain_ptr = malloc(sizeof(Domain_node));
		initDomainNode(set_domain_ptr);
	}
	if(NULL == global_conf.domain_list)
	{
		global_conf.domain_list = set_domain_ptr;

	}else{
		global_conf.domain_list_cur->next = set_domain_ptr;
		global_conf.domain_list_cur = set_domain_ptr;
	}
	memcpy(set_domain_ptr->domainName,urlName,nameLen);
        set_domain_ptr->domainName[nameLen]='\0';
	//qos, free first,and set
	free_qos_list(set_domain_ptr->qos_list);

	/*
	 *baseData-- {"protect_level":"high","threshold_url":"100","threshold_srcip":"100","qos":{"policy":[{"https":"false","srcip":"1.1.1.1","url":"letv.com","each_srcip":"false","each_url":"false","value":"100"},{...}]}}
	 *trustData--{"trust_list":[{"srcip":"1.1.1.1","url":"letv.com"},{..}]}
	 *blockData--{"block_list":[{"srcip":"1.1.1.1","url":"letv.com"},{..}]}
	 *
	 **/
	cJSON* pJson = cJSON_Parse(baseData);
	if(NULL==pJson){
		traceEvent("Json parse domain base conf failed and return",urlName,"WARN");
		return;
	}

		char protect_level[8];
		char threshold_url[8];
		char threshold_srcip[8];
	cJSON* pPlevel = cJSON_GetObjectItem(pJson,"protect_level");
	if(NULL!=pPlevel){
		//get protect_level
		strcpy(protect_level,pPlevel->valuestring);
	}
   cJSON* pThold_url = cJSON_GetObjectItem(pJson,"threshold_url");
	if(NULL!=pThold_url){
		//get protect_level
		strcpy(threshold_url,pThold_url->valuestring);
	}	
 cJSON* pThold_srcip = cJSON_GetObjectItem(pJson,"threshold_srcip");
	if(NULL!=pThold_srcip){
		//get protect_level
		strcpy(threshold_srcip,pThold_srcip->valuestring);
	}	
	char msg[1024];
	sprintf(msg,"level:%s,T_url:%s,T_srcip:%s",protect_level,threshold_url,threshold_srcip);
	traceEvent("Get base conf ",msg,"INFO");

	//	xmlDocPtr pdoc = xmlParseMemory(baseData,baseLen);
//	xmlNodePtr root = xmlDocGetRootElement(pdoc);
//	//xmlNodePtr qosNodePtr = root->xmlChildrenNode;
//	xmlChar* protectpath = ("/root/Protect");
//	xmlXPathObjectPtr protect_result = getNodeset(pdoc,protectpath);
//	if(NULL==protect_result){
//		traceEvent("Get Protect xml fail",urlName,"WARN");
//		return;
//	}
//	int i=0;
//	xmlNodeSetPtr Pnodeset = protect_result->nodesetval;
//	xmlNodePtr cur;
//    for(i=0;i<Pnodeset->nodeNr;i++){
//        cur = Pnodeset->nodeTab[i];
//		char level[8];
//		char th_srip[10];
//		char th_url[10];
//		char* levelptr = xmlGetProp(cur,(const xmlChar*)"level");
//		char* th_srcip_ptr = xmlGetProp(cur,(const xmlChar*)"threshold_srcip");
//		char* th_url_ptr = xmlGetProp(cur,(const xmlChar*)"threshold_url");
//		fprintf(stderr,"protect level:%s th_srcip:%s th_url:%s\n",levelptr,th_srcip_ptr,th_url_ptr);

//	}
/* 
	xmlChar* qospath = ("/root/Qos/item");
	xmlXPathObjectPtr qos_result = getNodeset(pdoc,qospath);

	xmlNodePtr subNode = xmlChildrenNode;
	Qos_node* qos_ptr = set_domain_ptr->qos_list;
	while(qosNodePtr){
		qos_ptr = malloc(Qos_node);
		
	}
	//fprintf(stdout,"log_leve:%s",xmlGetProp(root,"log_level"));
	//fflush(stdout);
*/


}








void parseMac(char *pMsg)
{
    int i, cnt;
    char macString[LENGTH] = "";
    char macCmd[LENGTH] = "";
    cJSON *pJson = cJSON_Parse(pMsg);
    if(!pJson)
    {
        printf("Can't parse mac policy!\n");
        return;
    }
    cnt = cJSON_GetArraySize(pJson);
    for (i = 0; i < cnt; i++)
    {
        cJSON *pArrayItem = cJSON_GetArrayItem(pJson, i);
        cJSON *ip = cJSON_GetObjectItem(pArrayItem, "ip");
        memset(macString, 0, LENGTH);
        strcat(macString, ip->valuestring);
        strcat(macString, " ");
        strcpy(macIp, ip->valuestring);

        cJSON *mac = cJSON_GetObjectItem(pArrayItem, "mac");
        strcat(macString, mac->valuestring);
        strcat(macString, "\n");
        sprintf(macCmd, "/usr/local/bin/gethopmac -a %s %s", ip->valuestring, mac->valuestring);
        system(macCmd);
        memset(macCmd, 0, sizeof(macCmd));

        int fd = open(IPMAC_CONFIG_FILE, O_RDWR | O_CREAT | O_APPEND, S_IRWXU);
        if((write(fd, macString, strlen(macString))) == 0)
        {
            printf("Error writing to the file.\n");
            cJSON_Delete(pJson);
            return;
        }
        close(fd);
    }
    cJSON_Delete(pJson);
}

void parseInject(const char *pMsg)
{
    int i, cnt;
    char injectString[LENGTH] = "";
    char injectCmd[LENGTH] = "";
    char nexthopStr[DATA_LENGTH] = "";
    char daemonStr[LENGTH] = "";

    cJSON * pJson = cJSON_Parse(pMsg);
    if(NULL == pJson)
    {
        return ;
    }

    cJSON *ip = cJSON_GetObjectItem(pJson, "ip");
    strcpy(injectIp, ip->valuestring);

    strcat(injectString, ip->valuestring);
    strcat(injectString, " ");

    cJSON *mask = cJSON_GetObjectItem(pJson, "mask");
    strcpy(injectMask, mask->valuestring);

    strcat(injectString, mask->valuestring);
    strcat(injectString, " ");

    cJSON *nexthop = cJSON_GetObjectItem(pJson, "nexthop");
    if(nexthop != NULL)
    {
        cnt = cJSON_GetArraySize(nexthop);
        for (i = 0; i < cnt; i++)
        {
            cJSON *pArrayItem = cJSON_GetArrayItem(nexthop, i);
            strcat(nexthopStr, pArrayItem->valuestring);
            strcat(nexthopStr, " ");
        }
    }
    strcat(injectString, nexthopStr);
    injectString[strlen(injectString) -1] = '\n';
    cJSON *daemon = cJSON_GetObjectItem(pJson, "daemon");
    if(daemon != NULL)
    {
        cnt = cJSON_GetArraySize(daemon);
        for (i = 0; i < cnt; i++)
        {
            cJSON *pArrayItem = cJSON_GetArrayItem(daemon, i);
            strcat(daemonStr, pArrayItem->valuestring);
            strcat(daemonStr, " ");
        }
    }
    sprintf(injectCmd, "/usr/local/bin/setinject -a %s %s %s", ip->valuestring, mask->valuestring, nexthopStr);
    system(injectCmd);

    int fd = open(INJECT_CONFIG_FILE, O_RDWR | O_CREAT | O_APPEND, S_IRWXU);
    if((write(fd, injectString, strlen(injectString))) == 0)
    {
        printf("Error writing to the file.\n");
        cJSON_Delete(pJson);
        return;
    }
    close(fd);
    cJSON_Delete(pJson);
}

void parseInterface(char *pMsg)
{
    int i, j, n, cnt, childNum;
    char interfaceCmd[LENGTH] = "";
    char interfaceString[LENGTH] = "";
    char list[LENGTH]="";
    int vlanFlag = 0;

    cJSON * pJson = cJSON_Parse(pMsg);
    if(NULL == pJson)
    {
        return ;
    }
    childNum = cJSON_GetArraySize(pJson);
    for(i = 0; i < childNum; i++)
    {
        cJSON *pArrayItem = cJSON_GetArrayItem(pJson, i);
        cJSON *ip = cJSON_GetObjectItem(pArrayItem, "ip");
        strcpy(interfaceIp, ip->valuestring);
        strcat(interfaceString, ip->valuestring);
        strcat(interfaceString, " ");

        cJSON *mask = cJSON_GetObjectItem(pArrayItem, "mask");
        strcat(interfaceString, mask->valuestring);
        strcat(interfaceString, " ");

        cJSON *vlanid = cJSON_GetObjectItem(pArrayItem, "vlanid");
        if(strlen(vlanid->valuestring) == 0)
        {
            vlanFlag = 0;
            strcat(interfaceString, "0 ");
        }
        else
        {
            vlanFlag = 1;
            strcat(interfaceString, vlanid->valuestring);
            strcat(interfaceString, " ");
        }
        cJSON *portlist =cJSON_GetObjectItem(pArrayItem, "portlist");
        cnt = cJSON_GetArraySize(portlist);
        for(j=0;j<cnt;j++)
        {
            cJSON *portArray = cJSON_GetArrayItem(portlist, j);
            strcat(list, portArray->valuestring);
            strcat(list, " ");
        }
        strcat(interfaceString, list);
        strcat(interfaceString, "\n");
        for(n=0;list[n];n++)
            if(list[n]=='/') list[n]=' ';

        if(vlanFlag == 0)
        {
            sprintf(interfaceCmd, "/usr/local/bin/interface -a %s %s vlan 0 port %s", ip->valuestring, mask->valuestring, list);
            system(interfaceCmd);
            printf("============%s===========\n",interfaceCmd);
        }
        else
        {
            sprintf(interfaceCmd, "/usr/local/bin/interface -a %s %s vlan %s port %s", ip->valuestring, mask->valuestring, vlanid->valuestring, list);
            system(interfaceCmd);
            printf("============%s===========\n",interfaceCmd);
        }
        system(interfaceCmd);

        int fd = open(INTERFACE_CONFIG_FILE, O_RDWR | O_CREAT | O_APPEND, S_IRWXU);
        if ((write(fd, interfaceString, strlen(interfaceString))) == 0)
        {
            printf("Error writing to the file.\n");
            return;
        }
        close(fd);
        memset(interfaceString, 0, LENGTH);
        memset(interfaceCmd, 0, LENGTH);
        memset(list, 0, LENGTH);
    }
    cJSON_Delete(pJson);
}

void parseGlobalPolicy(char *pMsg)
{
    int i ,cnt;
    int methods = 0, methods2 = 0;
    char globalString[5000] = "";
    char icmp[LENGTH]="";

    cJSON * pJson = cJSON_Parse(pMsg);
    if(NULL == pJson)
    {
        printf("global policy: %s\n", pMsg);
        printf("parse global policy error\n");
        return ;
    }
    strcat(globalString, "/usr/local/bin/setfilter 5 1\n");

    cJSON * pSubUdp = cJSON_GetObjectItem(pJson, "udp");
    if(pSubUdp != NULL)
    {
        int threshold;
        char udp[LENGTH]="";

        cJSON * udpThreshold = cJSON_GetObjectItem(pSubUdp, "threshold");
        threshold = atoi(udpThreshold->valuestring) * ZOOM;
        sprintf(udp, "/usr/local/bin/globalpolicy -w udp1=%d\n", threshold);
        strcat(globalString, udp);

        cJSON *udpEnable = cJSON_GetObjectItem(pSubUdp, "enable");
        cJSON *udpLimit = cJSON_GetObjectItem(pSubUdp, "limit");
        if(udpLimit != NULL)
        {
            char udpLimitString[LENGTH]="";
            char value[LENGTH]="";
            cJSON * udpLimitEnable = cJSON_GetObjectItem(udpLimit, "enable");
            cJSON *udpLimitValue = cJSON_GetObjectItem(udpLimit, "value");

            cJSON *udpLimitSip = cJSON_GetObjectItem(udpLimit, "sip");
            sprintf(udpLimitString, "/usr/local/bin/setflag -j %s %s 0 1\n", udpLimitSip->valuestring, udpLimitValue->valuestring);
            strcat(globalString, udpLimitString);
            cJSON *udpLimitDport = cJSON_GetObjectItem(udpLimit, "dport");
            cJSON *udpLimitSport = cJSON_GetObjectItem(udpLimit, "sport");
            cJSON *udpLimitDip = cJSON_GetObjectItem(udpLimit, "dip");
        }

        cJSON *udpMethods = cJSON_GetObjectItem(pSubUdp, "methods");
        if(udpMethods != NULL)
        {
            cnt = cJSON_GetArraySize(udpMethods);
            for (i = 0; i < cnt; i++)
            {
                cJSON *pArrayItem = cJSON_GetArrayItem(udpMethods, i);
                if(!strcmp(pArrayItem->valuestring, "1"))
                        methods = 1;
                if(!strcmp(pArrayItem->valuestring, "2"))
                    methods2 = 2;
            }
            if(!strcmp(udpEnable->valuestring, "1"))
                strcat(globalString, "/usr/local/bin/setfilter 3 1\n");
            else
                strcat(globalString, "/usr/local/bin/setfilter 3 64\n");

            if(methods2 == 2 && !strcmp(udpEnable->valuestring, "1"))
                strcat(globalString, "/usr/local/bin/setflag -a 97\n");
            else
                strcat(globalString, "/usr/local/bin/setflag -a 96\n");
        }
    }
    cJSON * pSubHttp = cJSON_GetObjectItem(pJson, "http");
    if( pSubHttp != NULL)
    {
        char http[LENGTH]="";
        cJSON * httpThreshold = cJSON_GetObjectItem(pSubHttp, "threshold");
        if(NULL != httpThreshold)
        {
            sprintf(http, "/usr/local/bin/setcc -s 2 %s\n", httpThreshold->valuestring);
            strcat(globalString, http);
            memset(http, 0, LENGTH);

            int threshold;
            threshold = atoi(httpThreshold->valuestring)*ZOOM;
            sprintf(http, "/usr/local/bin/setcc -s 2 %d\n", threshold);
            strcat(globalString, http);
        }
        cJSON *httpEnable = cJSON_GetObjectItem(pSubHttp, "enable");
        cJSON *httpMethods = cJSON_GetObjectItem(pSubHttp, "methods");
        if(httpMethods != NULL)
        {
            char methods[LENGTH]="";
            cnt = cJSON_GetArraySize(httpMethods);
            for (i = 0; i < cnt; i++)
            {
                cJSON *pArrayItem = cJSON_GetArrayItem(httpMethods, i);
                if(i == 0 && !strcmp(httpEnable->valuestring, "1"))
                {
                    sprintf(methods, "/usr/local/bin/setcc -s 1 %s\n", pArrayItem->valuestring);
                    strcat(globalString, methods);
                }
                else
                {
                    sprintf(methods, "/usr/local/bin/setcc -s 1 0\n");
                    strcat(globalString, methods);
                }
            }
        }
        cJSON *httpPort = cJSON_GetObjectItem(pSubHttp, "port");
        char port[LENGTH]="";
        sprintf(port, "/usr/local/bin/setcc -s 6 %s\n", httpPort->valuestring);
        strcat(globalString, port);
    }

    cJSON * pSubHttps = cJSON_GetObjectItem(pJson, "https");
    if(pSubHttps != NULL)
    {
        char threshold[LENGTH]="", enable [LENGTH]="", https[LENGTH]="";
        cJSON * pSubSubHttps = cJSON_GetObjectItem(pSubHttps, "threshold");
        if(NULL != pSubSubHttps)
        {
            strcpy(threshold, pSubSubHttps->valuestring);
        }
        pSubSubHttps = cJSON_GetObjectItem(pSubHttps, "enable");
        strcpy(enable, pSubSubHttps->valuestring);
        pSubSubHttps = cJSON_GetObjectItem(pSubHttps, "port");
        sprintf(https, "/usr/local/bin/setapp -https -a %s %s %s 0\n", enable, threshold, pSubSubHttps->valuestring);
        strcat(globalString, https);

        cJSON *httpsMethods = cJSON_GetObjectItem(pSubHttps, "methods");
        if(httpsMethods != NULL)
        {
            cnt = cJSON_GetArraySize(httpsMethods);
            for (i = 0; i < cnt; i++)
            {
                cJSON *pArrayItem = cJSON_GetArrayItem(httpsMethods, i);
            }
        }
    }

    cJSON * pSubAck = cJSON_GetObjectItem(pJson, "ack");
    if( pSubAck != NULL)
    {
        cJSON * ackThreshold = cJSON_GetObjectItem(pSubAck, "threshold");
        if(NULL != ackThreshold)
        {
            int threshold;
            char ack[LENGTH]="";
            threshold = atoi(ackThreshold->valuestring)*ZOOM;

            sprintf(ack, "/usr/local/bin/globalpolicy -w ack1=%d\n", threshold);
            strcat(globalString, ack);
        }
        cJSON *ackEnable = cJSON_GetObjectItem(pSubAck, "enable");

        cJSON *ackMethods = cJSON_GetObjectItem(pSubAck, "methods");
        if(ackMethods != NULL)
        {
            cnt = cJSON_GetArraySize(ackMethods);
            for (i = 0; i < cnt; i++)
            {
                cJSON *pArrayItem = cJSON_GetArrayItem(ackMethods, i);
                if(!strcmp(pArrayItem->valuestring, "1"))
                        methods = 1;
                if(!strcmp(pArrayItem->valuestring, "2"))
                        methods2 = 2;
            }
        }
        if(!strcmp(ackEnable->valuestring, "1"))
            strcat(globalString, "/usr/local/bin/setfilter 2 1\n");
        else
            strcat(globalString, "/usr/local/bin/setfilter 2 64\n");
        if(methods == 2 && !strcmp(ackEnable->valuestring, "1"))
            strcat(globalString, "/usr/local/bin/setflag -E 1\n");
        else
            strcat(globalString, "/usr/local/bin/setflag -E 0\n");
    }

    cJSON * pSubSyn = cJSON_GetObjectItem(pJson, "syn");
    if(pSubSyn != NULL)
    {
        cJSON * synThreshold = cJSON_GetObjectItem(pSubSyn, "threshold");
        if(NULL != synThreshold)
        {
            int threshold;
            char syn[LENGTH]="";
            threshold = atoi(synThreshold->valuestring)*ZOOM;
            sprintf(syn, "/usr/local/bin/globalpolicy -w syn1=%d\n", threshold);
            strcat(globalString, syn);
        }
        cJSON *synEnable = cJSON_GetObjectItem(pSubSyn, "enable");
        cJSON *synLimit = cJSON_GetObjectItem(pSubSyn, "limit");
        if(synLimit != NULL)
        {
            char synEnable[LENGTH]="", synValue[LENGTH]="";
            int value, dportflag, dipflag;
            cJSON * synLimitEnable = cJSON_GetObjectItem(synLimit, "enable");
            sprintf(synEnable, "/usr/local/bin/setflag -r %s\n", synLimitEnable->valuestring);
            strcat(globalString, synEnable);

            cJSON *synLimitValue = cJSON_GetObjectItem(synLimit, "value");
            value = atoi(synLimitValue->valuestring)*ZOOM;
            sprintf(synValue, "/usr/local/bin/setflag -k %d\n", value);
            strcat(globalString, synValue);
            cJSON *synLimitSip = cJSON_GetObjectItem(synLimit, "sip");
            cJSON *synLimitDport = cJSON_GetObjectItem(synLimit, "dport");
            if(!strcmp(synLimitDport->valuestring, "1"))
                dportflag=1;

            cJSON *synLimitSport = cJSON_GetObjectItem(synLimit, "sport");
            cJSON *synLimitDip = cJSON_GetObjectItem(synLimit, "dip");
            if(!strcmp(synLimitDip->valuestring, "1"))
                dipflag=1;

            if(dportflag == 1 && dipflag ==1)
                strcat(globalString, "/usr/local/bin/setflag -d 0\n");
            else if(dipflag == 1)
                strcat(globalString, "/usr/local/bin/setflag -d 1\n");
        }
        cJSON *synMethods = cJSON_GetObjectItem(pSubSyn, "methods");
        if(synMethods != NULL)
        {
            cnt = cJSON_GetArraySize(synMethods);
            for (i = 0; i < cnt; i++)
            {
                cJSON *pArrayItem = cJSON_GetArrayItem(synMethods, i);
                if(!strcmp(pArrayItem->valuestring, "1"))
                    methods = 1;
                if(!strcmp(pArrayItem->valuestring, "11"))
                    methods2 = 11;
            }
        }
        if(!strcmp(synEnable->valuestring, "1"))
            strcat(globalString, "/usr/local/bin/setfilter 1 1\n");
        else
            strcat(globalString, "/usr/local/bin/setfilter 1 64\n");

        if(methods2 == 11 && !strcmp(synEnable->valuestring, "1"))
            strcat(globalString, "/usr/local/bin/setflag -G 1\n");
        else
            strcat(globalString, "/usr/local/bin/setflag -G 0\n");
    }

    cJSON * pSubDns = cJSON_GetObjectItem(pJson, "dns");
    cJSON * pSubSubDns = cJSON_GetObjectItem(pSubDns, "threshold");
    if(NULL != pSubSubDns)
    {
        int threshold;char dns[LENGTH]="";
        threshold = atoi(pSubSubDns->valuestring)*ZOOM;
        sprintf(dns, "/usr/local/bin/globalpolicy -w dns_echo_limit=%d\n", threshold);
        strcat(globalString, dns);
    }
    pSubSubDns = cJSON_GetObjectItem(pSubDns, "enable");
    cJSON *dnsMethods = cJSON_GetObjectItem(pSubDns, "methods");
    if(dnsMethods != NULL)
    {
        char methods[LENGTH]="";
        cnt = cJSON_GetArraySize(dnsMethods);
        for (i = 0; i < cnt; i++)
        {
            cJSON *pArrayItem = cJSON_GetArrayItem(dnsMethods, i);
            if(i == 0)
            {
                sprintf(methods, "/usr/local/bin/setflag -u %s\n",pArrayItem->valuestring);
                strcat(globalString, methods);
            }
        }
    }
    pSubSubDns = cJSON_GetObjectItem(pSubDns, "port");

    cJSON * pSubLhttp = cJSON_GetObjectItem(pJson, "lhttp");
    cJSON * lhttpThreshold = cJSON_GetObjectItem(pSubLhttp, "threshold");
    int threshold;char lhttp[LENGTH]="";

    threshold = atoi(lhttpThreshold->valuestring)*ZOOM;
    sprintf(lhttp, "/usr/local/bin/setcc -s 13 %d\n", threshold);
    strcat(globalString, lhttp);
    memset(lhttp, 0, LENGTH);

    cJSON *lhttpEnable = cJSON_GetObjectItem(pSubLhttp, "enable");
    cJSON *lhttpPort = cJSON_GetObjectItem(pSubLhttp, "port");
    sprintf(lhttp, "/usr/local/bin/setcc -s 12 %s\n", lhttpPort->valuestring);
    strcat(globalString, lhttp);

    cJSON *portMethods = cJSON_GetObjectItem(pSubLhttp, "methods");
    if(portMethods != NULL)
    {
        cnt = cJSON_GetArraySize(portMethods);
        for (i = 0; i < cnt; i++)
        {
            cJSON *pArrayItem = cJSON_GetArrayItem(portMethods, i);
            if(!strcmp(pArrayItem->valuestring, "1"))
                methods = 1;
        }
        if(!strcmp(lhttpEnable->valuestring, "1"))
            strcat(globalString, "/usr/local/bin/setcc -s 14 1\n");
        else
            strcat(globalString, "/usr/local/bin/setcc -s 14 64\n");
    }

    cJSON * pSubIcmp = cJSON_GetObjectItem(pJson, "icmp");
    cJSON * icmpThreshold = cJSON_GetObjectItem(pSubIcmp, "threshold");
    sprintf(icmp, "/usr/local/bin/globalpolicy -w icmp1=%d\n", atoi(icmpThreshold->valuestring) * ZOOM);
    strcat(globalString, icmp);

    cJSON *icmpEnable = cJSON_GetObjectItem(pSubIcmp, "enable");
    cJSON *icmpMethods = cJSON_GetObjectItem(pSubIcmp, "methods");
    if(icmpMethods != NULL)
    {
        cnt = cJSON_GetArraySize(icmpMethods);
        for (i = 0; i < cnt; i++)
        {
            cJSON *pArrayItem = cJSON_GetArrayItem(icmpMethods, i);
            if(!strcmp(pArrayItem->valuestring, "1"))
                methods = 1;
        }
        if(!strcmp(icmpEnable->valuestring, "1"))
            strcat(globalString, "/usr/local/bin/setfilter 4 1\n");
        else
            strcat(globalString, "/usr/local/bin/setfilter 4 64\n");
    }
    cJSON * pSubOutLimit = cJSON_GetObjectItem(pJson, "outlimit");
    globalOutLimit = atoi(pSubOutLimit->valuestring);

    int fd = open(GLOBAL_POLICY, O_RDWR | O_CREAT, S_IRWXU);
    if((write(fd, globalString, strlen(globalString))) == 0)
    {
        printf("Error writing to the file.\n");
        return;
    }
    close(fd);
    cJSON_Delete(pJson);
}

void parsePolicy(const char* pMsg)
{
    int i ,cnt, fd;
    int tcpAckMethods = 0;
    int tcpSynMethods = 0;
    int tcpSynLimit = 0;

    char slowatkString[LENGTH] = "";char postString[LENGTH] = "";
    /*char icmpString[LENGTH] = "";*/char flagSetTcp[LENGTH] = "";
    char writeString[LENGTH] = "";char configName[LENGTH] = "";
    char groupParser[LENGTH] = "";char groupString[LENGTH] = "";
    char udpString[LENGTH] = "";char httpString[LENGTH] = "";
    char httpsString[LENGTH] = "";char ackString[LENGTH] = "";
    char synString[LENGTH] = "";char dnsString[LENGTH] = "";
    char outLimit[LENGTH] = "";char group_ip[LENGTH] = "";
    char groupIpCmd[LENGTH] = "";char nameString[LENGTH] = "";
    char udpConfig[DATA_LENGTH] = "";char ccConfig[DATA_LENGTH] = "";

    char baseString[LENGTH] = "-ddos CONN 1 64\n-ddos MAX_FLOW 1 0 1000 64\n-syncookieurl 1\n-sip 1 1 0 1 65535 5060\n-flagset_trustip 1 1 0 100 100 2 30\n-re_enable 1\n";

    sprintf(outLimit, " %d", globalOutLimit);
    cJSON * pJson = cJSON_Parse(pMsg);
    if(NULL == pJson)
    {
        traceEvent("Parse group policy ", "format", "ERROR");
        return ;
    }

    cJSON *groupIp = cJSON_GetObjectItem(pJson, "groupIp");
    if(groupIp != NULL)
    {
        cnt = cJSON_GetArraySize(groupIp);
        for (i = 0; i < cnt; i++)
        {
            cJSON *pArrayItem = cJSON_GetArrayItem(groupIp, i);
            if(INADDR_NONE != inet_addr(pArrayItem->valuestring))
            {
                char tmpBuf[LENGTH] = "";
                sprintf(tmpBuf, "%s-%s", pArrayItem->valuestring, pArrayItem->valuestring);
                memset(pArrayItem->valuestring, 0, strlen(pArrayItem->valuestring));
                strcpy(pArrayItem->valuestring, tmpBuf);
            }
            strcat(groupIpCmd, pArrayItem->valuestring);
            strcat(groupIpCmd, " ");
        }
        sprintf(group_ip,"-group_ip %s\n", groupIpCmd);
    }

    cJSON *groupId = cJSON_GetObjectItem(pJson, "groupId");
    if(groupId != NULL)
    {
        sprintf(nameString, "-name %s\n", groupId->valuestring);
    }

    sprintf(configName, "%s/%s", GROUP_POLICY_FILE_DIR, groupId->valuestring);
    fd = open(configName, /*O_RDWR | O_CREAT*/O_WRONLY | O_CREAT, S_IRWXU);
    printf("%s", baseString);
    if((write(fd, baseString, strlen(baseString))) == 0)
    {
        traceEvent("write to file faild ", configName, "ERROR");
        return ;
    }
    printf("%s", nameString);
    if((write(fd, nameString, strlen(nameString))) == 0)
    {
        traceEvent("write to file faild ", configName, "ERROR");
        return;
    }
    printf("%s", group_ip);
    if((write(fd, group_ip, strlen(group_ip))) == 0)
    {
        traceEvent("write to file faild ", configName, "ERROR");
        return;
    }

    cJSON *policy = cJSON_GetObjectItem(pJson, "policy");
    if(policy == NULL)
    {
        cJSON_Delete(pJson);
        traceEvent("Parse group policy ", "format", "ERROR");
        return;
    }
    cJSON * pSubUdp = cJSON_GetObjectItem(policy, "udp");
    if( pSubUdp != NULL)
    {
        int methods = 0, methods2 = 0;
        char limit1[5] = "";
        char limit2[5] = "";
        char limit3[5] = "";
        char limit4[5] = "";
        char flagSetUdp[LENGTH] = "";
        cJSON * udpThreshold = cJSON_GetObjectItem(pSubUdp, "threshold");
        cJSON *udpEnable = cJSON_GetObjectItem(pSubUdp, "enable");
        if(udpEnable != NULL)
            sprintf(udpString, "-ddos UDP 1 ");
        if(udpThreshold != NULL)
            strcat(udpString, udpThreshold->valuestring);

        cJSON *udpLimit = cJSON_GetObjectItem(pSubUdp, "limit");
        if(udpLimit != NULL)
        {
            cJSON *udpLimitEnable = cJSON_GetObjectItem(udpLimit, "enable");
            cJSON *udpLimitValue = cJSON_GetObjectItem(udpLimit, "value");
            cJSON *udpLimitSip = cJSON_GetObjectItem(udpLimit, "sip");
            cJSON *udpLimitDport = cJSON_GetObjectItem(udpLimit, "dport");
            cJSON *udpLimitSport = cJSON_GetObjectItem(udpLimit, "sport");
            cJSON *udpLimitDip = cJSON_GetObjectItem(udpLimit, "dip");

            if(!strcmp(udpLimitSip->valuestring, "1") && !strcmp(udpLimitSport->valuestring, "1"))
                sprintf(limit1, "1");
            else
                sprintf(limit1, "0");

            if(!strcmp(udpLimitSip->valuestring, "1") && strcmp(udpLimitSport->valuestring, "1"))
                sprintf(limit2, "1");
            else
                sprintf(limit2, "0");

            if(!strcmp(udpLimitDip->valuestring, "1") && !strcmp(udpLimitDport->valuestring, "1"))
                sprintf(limit3, "1");
            else
                sprintf(limit3, "0");

            if(!strcmp(udpLimitDip->valuestring, "1") && strcmp(udpLimitDport->valuestring, "1"))
                sprintf(limit4, "1");
            else
                sprintf(limit4, "0");
        }
        cJSON *udpMethods = cJSON_GetObjectItem(pSubUdp, "methods");
        if(udpMethods != NULL)
        {
            cnt = cJSON_GetArraySize(udpMethods);
            for (i = 0; i < cnt; i++)
            {
                cJSON *pArrayItem = cJSON_GetArrayItem(udpMethods, i);
                if(!strcmp(pArrayItem->valuestring, "1"))
                    methods = 1;
                if(!strcmp(pArrayItem->valuestring, "2"))
                    methods2 = 1;
            }
            if(methods == 1 && !strcmp(udpEnable->valuestring, "1"))
            {
                strcat(udpString, " 1\n");
                strcat(flagSetUdp, "-flagset_udp 1 1 0 80\n");
            }
            else
            {
                strcat(udpString, " 64\n");
                strcat(flagSetUdp, "-flagset_udp 1 0 0 80\n");
            }
            if(methods2 == 1 && !strcmp(udpEnable->valuestring, "1"))
                sprintf(udpConfig, "-udp 1 1 0 65535 1 %s 65535 %s 3000000 %s 65535 %s 3000000\n", limit1, limit2, limit3, limit4);
            else
                sprintf(udpConfig, "-udp 1 0 0 65535 1 %s 65535 %s 3000000 %s 65535 %s 3000000\n", limit1, limit2, limit3, limit4);

            printf("%s", udpConfig);
            if((write(fd, udpConfig, strlen(udpConfig))) == 0)
            {
                traceEvent("write to file faild ", configName, "ERROR");
                return;
            }
            printf("%s", udpString);
            if((write(fd, udpString, strlen(udpString))) == 0)
            {
                traceEvent("write to file faild ", configName, "ERROR");
                return;
            }
            printf("%s", flagSetUdp);
            if((write(fd, flagSetUdp, strlen(flagSetUdp))) == 0)
            {
                traceEvent("write to file faild ", configName, "ERROR");
                return;
            }
        }
    }
    cJSON * pSubHttp = cJSON_GetObjectItem(policy, "http");
    if( pSubHttp != NULL)
    {
        char ccMetholds[5] = "";
        cJSON *httpThreshold = cJSON_GetObjectItem(pSubHttp, "threshold");

        cJSON *httpEnable = cJSON_GetObjectItem(pSubHttp, "enable");
        cJSON *httpMethods = cJSON_GetObjectItem(pSubHttp, "methods");
        if(httpMethods != NULL)
        {
            cnt = cJSON_GetArraySize(httpMethods);
            for (i = 0; i < cnt; i++)
            {
                cJSON *pArrayItem = cJSON_GetArrayItem(httpMethods, i);
                if(i==0)
                    strcpy(ccMetholds, pArrayItem->valuestring);
            }
        }
        cJSON *httpPort = cJSON_GetObjectItem(pSubHttp, "port");
        sprintf(ccConfig, "-cc 1 %s %s %s %s 0 qq\n", httpThreshold->valuestring, httpPort->valuestring, httpEnable->valuestring, ccMetholds);
        printf("%s", ccConfig);
        if((write(fd, ccConfig, strlen(ccConfig))) == 0)
        {
            traceEvent("write to file faild ", configName, "ERROR");
            return;
        }
    }
    cJSON * pSubHttps = cJSON_GetObjectItem(policy, "https");
    if( pSubHttps != NULL)
    {
        char methods[LENGTH] = "";
        char port[LENGTH] = "";

        cJSON * httpsThreshold = cJSON_GetObjectItem(pSubHttps, "threshold");

        cJSON *httpsEnable = cJSON_GetObjectItem(pSubHttps, "enable");
        if(httpsEnable != NULL)
            sprintf(httpsString, "-https 1 %s ", httpsEnable->valuestring);
        if(httpsThreshold != NULL)
            strcat(httpsString, httpsThreshold->valuestring);
        cJSON *httpsPort = cJSON_GetObjectItem(pSubHttps, "port");
        if(httpsPort != NULL)
            sprintf(port, " %s 0\n", httpsPort->valuestring);
        strcat(httpsString, port);

        printf("%s", httpsString);
        if((write(fd, httpsString, strlen(httpsString))) == 0)
        {
            traceEvent("write to file faild ", configName, "ERROR");
            return;
        }
        cJSON *httpsMethods = cJSON_GetObjectItem(pSubHttps, "methods");
        if(httpsMethods != NULL)
        {
            cnt = cJSON_GetArraySize(httpsMethods);
            for (i = 0; i < cnt; i++)
            {
                cJSON *pArrayItem = cJSON_GetArrayItem(httpsMethods, i);
            }
        }
    }
    cJSON * pSubAck = cJSON_GetObjectItem(policy, "ack");
    if( pSubAck != NULL)
    {
        int methods = 0;
        cJSON * ackThreshold = cJSON_GetObjectItem(pSubAck, "threshold");
        if(ackThreshold != NULL)
        {
            sprintf(ackString, "-ddos ACK 1 %s", ackThreshold->valuestring);
        }
        cJSON *ackEnable = cJSON_GetObjectItem(pSubAck, "enable");
        cJSON *ackMethods = cJSON_GetObjectItem(pSubAck, "methods");
        if(ackMethods != NULL)
        {
            cnt = cJSON_GetArraySize(ackMethods);
            for (i = 0; i < cnt; i++)
            {
                cJSON *pArrayItem = cJSON_GetArrayItem(ackMethods, i);
                if(!strcmp(pArrayItem->valuestring, "1"))
                    methods = 1;
                if(!strcmp(pArrayItem->valuestring, "2"))
                    tcpAckMethods = 1;
            }
            if(methods == 1 && !strcmp(ackEnable->valuestring, "1"))
                strcat(ackString, " 1\n");
            else
                strcat(ackString, " 64\n");
        }
        printf("%s", ackString);
        if((write(fd, ackString, strlen(ackString))) == 0)
        {
            traceEvent("write to file faild ", configName, "ERROR");
            return;
        }
    }
    cJSON * pSubSyn = cJSON_GetObjectItem(policy, "syn");
    if(pSubSyn != NULL)
    {
        int methods = 0;
        cJSON *synLimitEnable;cJSON *synLimitValue;
        cJSON *synLimitSip;cJSON *synLimitDport;
        cJSON *synLimitSport;cJSON *synLimitDip;

        cJSON *synThreshold = cJSON_GetObjectItem(pSubSyn, "threshold");
        cJSON *synEnable = cJSON_GetObjectItem(pSubSyn, "enable");
        if(synEnable != NULL)
            sprintf(synString, "-ddos SYN 1 ");

        if(synThreshold != NULL)
            strcat(synString, synThreshold->valuestring);

        cJSON *synLimit = cJSON_GetObjectItem(pSubSyn, "limit");
        if(synLimit != NULL)
        {
            synLimitEnable = cJSON_GetObjectItem(synLimit, "enable");
            synLimitValue = cJSON_GetObjectItem(synLimit, "value");
            synLimitSip = cJSON_GetObjectItem(synLimit, "sip");
            synLimitDport = cJSON_GetObjectItem(synLimit, "dport");
            synLimitSport = cJSON_GetObjectItem(synLimit, "sport");
            synLimitDip = cJSON_GetObjectItem(synLimit, "dip");

            if(!strcmp(synLimitDip->valuestring, "1") && strcmp(synLimitDport->valuestring, "1"))
                tcpSynLimit = 0;
            if(!strcmp(synLimitDip->valuestring, "1"))
                tcpSynLimit = 1;
        }
        cJSON *synMethods = cJSON_GetObjectItem(pSubSyn, "methods");
        if(synMethods != NULL)
        {
            cnt = cJSON_GetArraySize(synMethods);
            for (i = 0; i < cnt; i++)
            {
                cJSON *pArrayItem = cJSON_GetArrayItem(synMethods, i);
                if(!strcmp(pArrayItem->valuestring, "1"))
                    methods = 1;
                if(!strcmp(pArrayItem->valuestring, "11"))
                    tcpSynMethods = 1;
            }
            if(methods == 1 && !strcmp(synEnable->valuestring, "1"))
            {
                strcat(synString, outLimit);
                strcat(synString, " 1 1\n");
            }
            else
            {
                strcat(synString, outLimit);
                strcat(synString, " 64 1\n");
            }
        }
        if(tcpSynMethods ==1 && !strcmp(synEnable->valuestring, "1"))
            sprintf(flagSetTcp, "-flagset_tcp 1 %s %s 0 %d %d 8 24 10000\n", synLimitEnable->valuestring, synLimitValue->valuestring, tcpSynLimit, tcpAckMethods);
        else
            sprintf(flagSetTcp, "-flagset_tcp 1 %s %s 1 %d %d 8 24 10000\n", synLimitEnable->valuestring, synLimitValue->valuestring, tcpSynLimit, tcpAckMethods);
        printf("%s", flagSetTcp);
        if((write(fd, flagSetTcp, strlen(flagSetTcp))) == 0)
        {
            printf("Error writing to the file.\n");
            return;
        }
        printf("%s", synString);
        if((write(fd, synString, strlen(synString))) == 0)
        {
            printf("Error writing to the file.\n");
            return;
        }
    }
    cJSON * pSubDns = cJSON_GetObjectItem(policy, "dns");
    cJSON * pSubSubDns = cJSON_GetObjectItem(pSubDns, "threshold");
    if(pSubSubDns != NULL)
    {
        cJSON *dnsEnable = cJSON_GetObjectItem(pSubDns, "enable");
        sprintf(dnsString, "-dns 1 %s 0 1 1%s\n", dnsEnable->valuestring, outLimit);

        printf("%s", dnsString);
        if((write(fd, dnsString, strlen(dnsString))) == 0)
        {
            printf("Error writing to the file.\n");
            return;
        }
        cJSON *dnsMethods = cJSON_GetObjectItem(pSubDns, "methods");
        if(dnsMethods != NULL)
        {
            cnt = cJSON_GetArraySize(dnsMethods);
            for(i = 0; i < cnt; i++)
            {
                cJSON *pArrayItem = cJSON_GetArrayItem(dnsMethods, i);
            }
        }
        cJSON *dnsPort = cJSON_GetObjectItem(pSubDns, "port");
    }
    cJSON * pSubLhttp = cJSON_GetObjectItem(policy, "lhttp");
    if(pSubLhttp != NULL)
    {
        cJSON * lhttpThreshold = cJSON_GetObjectItem(pSubLhttp, "threshold");
        cJSON *lhttpEnable = cJSON_GetObjectItem(pSubLhttp, "enable");
        printf("%s", slowatkString);
        sprintf(slowatkString, "-slowatk %s 500 %s\n", lhttpEnable->valuestring, lhttpThreshold->valuestring);
        if((write(fd, slowatkString, strlen(slowatkString))) == 0)
        {
            printf("Error writing to the file.\n");
            return;
        }

        cJSON *lhttpPort = cJSON_GetObjectItem(pSubLhttp, "port");
        sprintf(postString, "-post 1 %s %s 1 2\n", lhttpThreshold->valuestring, lhttpPort->valuestring);
        printf("%s", postString);
        if((write(fd, postString, strlen(postString))) == 0)
        {
            printf("Error writing to the file.\n");
            return;
        }

        cJSON *portMethods = cJSON_GetObjectItem(pSubLhttp, "methods");
        if(portMethods != NULL)
        {
            cnt = cJSON_GetArraySize(portMethods);
            for (i = 0; i < cnt; i++)
            {
                cJSON *pArrayItem = cJSON_GetArrayItem(portMethods, i);
            }
        }
    }
    int methosd = 0;
    cJSON * pSubIcmp = cJSON_GetObjectItem(policy, "icmp");
    if(pSubIcmp != NULL)
    {
        cJSON *icmpThreshold = cJSON_GetObjectItem(pSubIcmp, "threshold");
        cJSON *icmpEnable = cJSON_GetObjectItem(pSubIcmp, "enable");
        cJSON *icmpMethods = cJSON_GetObjectItem(pSubIcmp, "methods");
        if(icmpMethods != NULL)
        {
            char icmpString[LENGTH] = "";
            cnt = cJSON_GetArraySize(icmpMethods);
            for (i = 0; i < cnt; i++)
            {
                cJSON *pArrayItem = cJSON_GetArrayItem(icmpMethods, i);
                if(!strcmp(pArrayItem->valuestring, "1"))
                    methosd = 1;
            }
            if(methosd == 1 && !strcmp(icmpEnable->valuestring, "1"))
                sprintf(icmpString, "-ddos ICMP 1 %s 1\n", icmpThreshold->valuestring);
            else
                sprintf(icmpString, "-ddos ICMP 1 %s 64\n", icmpThreshold->valuestring);

            printf("%s", icmpString);
            if((write(fd, icmpString, strlen(icmpString))) == 0)
            {
                printf("Error writing to the file group policy config\n");
                return;
            }
            close(fd);
        }
    }
    sprintf(groupParser, "/usr/local/bin/groupparser -A %s", configName);
    system(groupParser);
    //close(fd);
    cJSON_Delete(pJson);
}

