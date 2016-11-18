#include "policyWatcher.h"
#include "commonStruct.h"
#define CC_CONF_PATH "/tmp/cc_conf/"
#define CC_CONF_ENGINE "/tmp/cc_conf_engine"
int SPACE_1M=1048576;
int SPACE_5M=1048576*5;
struct mylist myStr;
int initStatus=0,curStatus=0;
int loopRun=1;
static int mycount = 0, num = 0;
Global_conf global_conf;
int32_t current_version;
zhandle_t* zkhandle;
volatile bool aopt_busy = false;
char* PolicyBaseData;
char* PolicyTrustData;
char* PolicyBlockData;
static int connected = 0;
static int expired = 0;
char zkEnv[LENGTH] = "";
char* gTrue = "True";
char* gFalse = "False";


void set_aopt_busy(bool flag)
{
	aopt_busy = flag;
}
bool get_aopt_busy()
{
	return aopt_busy;
}
void get_zookeeper_env()
{
    sprintf(zkEnv ,"%s", getenv("ZOOKEEPER_HOME"));
    printf("zookeeper path = %s\n", zkEnv);
}
void outSysConf2File()
{
    /*
     * output msg to local file
     */
    Sys_conf* sys_node = &global_conf.sys_conf;
    //sys 
    cJSON* sys_json = cJSON_CreateObject();
    cJSON_AddItemToObject(sys_json,"log_level",cJSON_CreateNumber(sys_node->log_level));
    cJSON_AddItemToObject(sys_json,"log_timer",cJSON_CreateNumber(sys_node->log_timer));
    cJSON_AddItemToObject(sys_json,"enable",cJSON_CreateBool(sys_node->enable));
    char* out = cJSON_Print(sys_json); 
    char* outfile[URL_LENGTH+128];
    strcpy(outfile,CC_CONF_PATH);
    strcat(outfile,"_sys");
    if(0!=access(CC_CONF_PATH,F_OK)){
        traceEvent("CC_CONF_PATH not exists,create it ","","INFO");
        mkdir(CC_CONF_PATH,S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH);
    }
    FILE* fp = fopen(outfile,"w");
    fprintf(fp,"%s",out);
    fflush(fp);
    fclose(fp);
    free(out);
}
void outPolicy2File(Domain_node* domain_ptr)
{
    /*
     * out put policy to local file
     */

    traceEvent("Do outPolicy2File","","INFO");
    if(domain_ptr){
        //output single domain
        cJSON* policy_json = cJSON_CreateObject();
        cJSON_AddItemToObject(policy_json,"domain",cJSON_CreateString(domain_ptr->domainName));
        cJSON_AddItemToObject(policy_json,"cc_level",cJSON_CreateString(domain_ptr->cc_level));
        cJSON_AddItemToObject(policy_json,"threshold_url",cJSON_CreateNumber(domain_ptr->threshold_url));
        cJSON_AddItemToObject(policy_json,"threshold_srcip",cJSON_CreateNumber(domain_ptr->threshold_srcip));
        cJSON_AddItemToObject(policy_json,"enable",cJSON_CreateBool(domain_ptr->enable));
        //qos
        cJSON* qos_array = cJSON_CreateArray();
        cJSON_AddItemToObject(policy_json,"qos",qos_array);
        Qos_node* qos_tmp = domain_ptr->qos_list;
        while(qos_tmp){
            cJSON* qos_json = cJSON_CreateObject();
            if(qos_tmp->https)
                cJSON_AddItemToObject(qos_json,"https",cJSON_CreateTrue());
            else
                cJSON_AddItemToObject(qos_json,"https",cJSON_CreateFalse());
            if(qos_tmp->each_srcip)
                cJSON_AddItemToObject(qos_json,"each_srcip",cJSON_CreateTrue());
            else
                cJSON_AddItemToObject(qos_json,"each_srcip",cJSON_CreateFalse());
            if(qos_tmp->each_url)
                cJSON_AddItemToObject(qos_json,"each_url",cJSON_CreateTrue());
            else
                cJSON_AddItemToObject(qos_json,"each_url",cJSON_CreateFalse());
            cJSON_AddItemToObject(qos_json,"srcip",cJSON_CreateString(qos_tmp->srcip));
            cJSON_AddItemToObject(qos_json,"url",cJSON_CreateString(qos_tmp->url));
            cJSON_AddItemToObject(qos_json,"speed",cJSON_CreateNumber(qos_tmp->speed));
            cJSON_AddItemToArray(qos_array,qos_json);
            qos_tmp = qos_tmp->next;
        }
        //trust list
        cJSON* trust_array = cJSON_CreateArray();
        cJSON_AddItemToObject(policy_json,"trust_list",trust_array);
        Trust_block_table* trust_tmp = domain_ptr->trust_list;
        while(trust_tmp){
            cJSON* trust_json = cJSON_CreateObject();
            cJSON_AddItemToObject(trust_json,"srcip",cJSON_CreateString(trust_tmp->srcip));
            cJSON_AddItemToObject(trust_json,"url",cJSON_CreateString(trust_tmp->url));
            cJSON_AddItemToArray(trust_array,trust_json);
            trust_tmp = trust_tmp->next;
        }
        //block list
        cJSON* block_array = cJSON_CreateArray();
        cJSON_AddItemToObject(policy_json,"block_list",block_array);
        Trust_block_table* block_tmp = domain_ptr->block_list;
        while(block_tmp){
            cJSON* block_json = cJSON_CreateObject();
            cJSON_AddItemToObject(block_json,"srcip",cJSON_CreateString(block_tmp->srcip));
            cJSON_AddItemToObject(block_json,"url",cJSON_CreateString(block_tmp->url));
            cJSON_AddItemToArray(block_array,block_json);
            block_tmp = block_tmp->next;
        }
        char* out = cJSON_Print(policy_json);
        //clear old file
        char* outfile[URL_LENGTH+128];
        strcpy(outfile,CC_CONF_PATH);
        strcat(outfile,domain_ptr->domainName);
        if(0!=access(CC_CONF_PATH,F_OK)){
            traceEvent("CC_CONF_PATH not exists,create it ","","INFO");
            mkdir(CC_CONF_PATH,S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH);
        }
        FILE* fp = fopen(outfile,"w");
        fprintf(fp,"%s",out);
        fflush(fp);
        fclose(fp);
        free(out);
    }else{
        //output all domain

        outSysConf2File(); 
        Domain_node* node_tmp = global_conf.domain_list;
        while(node_tmp){
            cJSON* policy_json = cJSON_CreateObject();
            cJSON_AddItemToObject(policy_json,"domain",cJSON_CreateString(node_tmp->domainName));
            cJSON_AddItemToObject(policy_json,"cc_level",cJSON_CreateString(node_tmp->cc_level));
            cJSON_AddItemToObject(policy_json,"threshold_url",cJSON_CreateNumber(node_tmp->threshold_url));
            cJSON_AddItemToObject(policy_json,"threshold_srcip",cJSON_CreateNumber(node_tmp->threshold_srcip));
            cJSON_AddItemToObject(policy_json,"enable",cJSON_CreateBool(domain_ptr->enable));
            //qos
            cJSON* qos_array = cJSON_CreateArray();
            cJSON_AddItemToObject(policy_json,"qos",qos_array);
            Qos_node* qos_tmp = node_tmp->qos_list;
            while(qos_tmp){
                cJSON* qos_json = cJSON_CreateObject();
                if(qos_tmp->https)
                    cJSON_AddItemToObject(qos_json,"https",cJSON_CreateTrue());
                else
                    cJSON_AddItemToObject(qos_json,"https",cJSON_CreateFalse());
                if(qos_tmp->each_srcip)
                    cJSON_AddItemToObject(qos_json,"each_srcip",cJSON_CreateTrue());
                else
                    cJSON_AddItemToObject(qos_json,"each_srcip",cJSON_CreateFalse());
                if(qos_tmp->each_url)
                    cJSON_AddItemToObject(qos_json,"each_url",cJSON_CreateTrue());
                else
                    cJSON_AddItemToObject(qos_json,"each_url",cJSON_CreateFalse());
                cJSON_AddItemToObject(qos_json,"srcip",cJSON_CreateString(qos_tmp->srcip));
                cJSON_AddItemToObject(qos_json,"url",cJSON_CreateString(qos_tmp->url));
                cJSON_AddItemToObject(qos_json,"speed",cJSON_CreateNumber(qos_tmp->speed));
                cJSON_AddItemToArray(qos_array,qos_json);
                qos_tmp = qos_tmp->next;
            }
            //trust list
            cJSON* trust_array = cJSON_CreateArray();
            cJSON_AddItemToObject(policy_json,"trust_list",trust_array);
            Trust_block_table* trust_tmp = node_tmp->trust_list;
            while(trust_tmp){
                cJSON* trust_json = cJSON_CreateObject();
                cJSON_AddItemToObject(trust_json,"srcip",cJSON_CreateString(trust_tmp->srcip));
                cJSON_AddItemToObject(trust_json,"url",cJSON_CreateString(trust_tmp->url));
                cJSON_AddItemToArray(trust_array,trust_json);
                trust_tmp = trust_tmp->next;
            }
            //block list
            cJSON* block_array = cJSON_CreateArray();
            cJSON_AddItemToObject(policy_json,"block_list",block_array);
            Trust_block_table* block_tmp = node_tmp->block_list;
            while(block_tmp){
                cJSON* block_json = cJSON_CreateObject();
                cJSON_AddItemToObject(block_json,"srcip",cJSON_CreateString(block_tmp->srcip));
                cJSON_AddItemToObject(block_json,"url",cJSON_CreateString(block_tmp->url));
                cJSON_AddItemToArray(block_array,block_json);
                block_tmp = block_tmp->next;
            }
            char* out = cJSON_Print(policy_json);
            //clear old file
            char* outfile[URL_LENGTH+128];
            memset(outfile,0,URL_LENGTH+128);
            strcpy(outfile,CC_CONF_PATH);
            strcat(outfile,node_tmp->domainName);
            if(0!=access(CC_CONF_PATH,F_OK)){
                traceEvent("CC_CONF_PATH not exists,create it ","","INFO");
                mkdir(CC_CONF_PATH,S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH);
            }
            FILE* fp = fopen(outfile,"w");
            fprintf(fp,"%s",out);
            fflush(fp);
            fclose(fp);
            free(out);
            node_tmp = node_tmp->next;
        }
    }
}

void addSys2File()
{
    /*
     * output msg for engine commit
     */

	traceEvent("Do addSys2File","","INFO");
	Sys_conf* sys_node = &global_conf.sys_conf;
	FILE* fp = fopen(CC_CONF_ENGINE,"a+");
	char msg[1024];
	int msgLen = 1024;
	int msgPos = 0;
	int lenTmp = 0;
    char* enable_str = NULL;
    if(sys_node->enable){
        enable_str = gTrue;
    }else{
        enable_str = gFalse;
    }
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"AddSys{\n    log_level=%d,\n",sys_node->log_level);
	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"    log_timer=%d,\n    enable=%s\n    \}\n\n",sys_node->log_timer,enable_str);
	fprintf(fp,"%s",msg);
	fflush(fp);
	fclose(fp);
}

void addPolicy2File(Domain_node* node)
{
    /*
     * add msg for engine commit
     */
	traceEvent("Do addPolicy2File",node->domainName,"INFO");
	FILE* fp = fopen(CC_CONF_ENGINE,"a+");
	if(NULL==fp){
		traceEvent("Do addPolicy2File open file failed",node->domainName,"WARN");
		return;
	}
	char msg[1024];
	int msgLen = 1024;
	int msgPos = 0;
	int lenTmp = 0;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"AddPolicy{\n    domain=\"%s\",\n",node->domainName);
	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"    cc_level=\"%s\",\n",node->cc_level);
	msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"    threshold_srcip=%d,\n",node->threshold_srcip);
    msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"    threshold_url=%d,\n",node->threshold_url);
    msgPos = msgPos + lenTmp;
	lenTmp = snprintf(msg+msgPos,msgLen-msgPos,"    qos=\{\n");
	fprintf(fp,"%s",msg);
	Qos_node* qos_tmp = node->qos_list;
	bool first_f = true;
	while(qos_tmp){
		if(first_f){
			fprintf(fp,"        \{\n        srcip=\"%s\",\n",qos_tmp->srcip);
			first_f = false;
		}else{
			fprintf(fp,",\n        \{\n        srcip=\"%s\",\n",qos_tmp->srcip);
		}
		fprintf(fp,"        url=\"%s\",\n",qos_tmp->url);
		fprintf(fp,"        value=%d\n        \}",qos_tmp->speed);
		qos_tmp = qos_tmp->next;
	}
	fprintf(fp,"\n    \},\n");
	fflush(fp);
    //trust
	first_f = true;
	Trust_block_table* trust_tmp = node->trust_list;
	fprintf(fp,"    trust_list=\{\n");
	while(trust_tmp){
		if(first_f){
			fprintf(fp,"        \{\n        srcip=\"%s\",\n",trust_tmp->srcip);
			first_f = false;
		}else{
			fprintf(fp,",\n        \{\n        srcip=\"%s\",\n",trust_tmp->srcip);
		}
		fprintf(fp,"        url=\"%s\"\n        \}",trust_tmp->url);
		trust_tmp = trust_tmp->next;
	}
	fprintf(fp,"\n    \},\n");
	fflush(fp);
	//block
	first_f = true;
	Trust_block_table* block_tmp = node->block_list;
	fprintf(fp,"    block_list=\{\n");
	while(block_tmp){
		if(first_f){
			fprintf(fp,"        \{\n        srcip=\"%s\",\n",block_tmp->srcip);
			first_f = false;
		}else{
			fprintf(fp,",\n        \{\n        srcip=\"%s\",\n",block_tmp->srcip);
		}
		fprintf(fp,"        url=\"%s\"\n        \}",block_tmp->url);
		block_tmp = block_tmp->next;
	}
	fprintf(fp,"\n    \}\n\}\n\n");
	fflush(fp);
	fclose(fp);
	traceEvent("Do addPolicy2File end","","INFO");
}

bool tellEngineCommit()
{
    traceEvent("Do tellEngineCommit,need to do,set WARN first","","WARN");
    return true;
}

void main_watcher (zhandle_t *zkh, int type, int state, const char *path, void* context)
{
    if (type == ZOO_SESSION_EVENT) 
    {
        if (state == ZOO_CONNECTED_STATE) 
        {
            connected = 1;
            printf("connected...\n");
        } 
        else if (state == ZOO_CONNECTING_STATE) 
        {
            if(connected == 1) 
            {
                  traceEvent("Connecting zookeeper ", "disconnected", "ERROR");
                  printf("connecting...\n");
            }
            connected = 0;
        } 
        else if (state == ZOO_EXPIRED_SESSION_STATE) 
        {
            expired = 1;
            connected = 0;
            printf("connect expired...\n");
            traceEvent("Connect expired ", "session expired", "WARN");
            //zookeeper_close(zkh);
            //zkhandle = zookeeper_init("localhost:2181", main_watcher, 300000, 0, "hello zookeeper.", 0);
            //watchGetThread();
            //zookeeper_close(zkh);
        }
    }
}

void zkstatus_watch(zhandle_t* zh, int type, int state, const char* path, void* watcherCtx)
{
    int i=0;
    char childbuf[128] = "";
    char buffer1[64] = "";
    int bufferlen1=sizeof(buffer1);
    struct Stat stat;
    struct String_vector strings;
    if(type == ZOO_CREATED_EVENT)
    {
        traceEvent("Create status event ", path, "INFO");
    }
    if(type == ZOO_DELETED_EVENT)
    {
        traceEvent("监测到节点退出 ", path, "INFO");
    }
    if(type == ZOO_CHANGED_EVENT)
    {
        traceEvent("Watch status node changed ", path, "INFO");
    }
    if(type == ZOO_CHILD_EVENT)
    {
        int flag = zoo_wget_children2(zh, path, zkstatus_watch, watcherCtx, &strings, &stat);
        if(flag==ZOK)
        {
            for(i=0;i<strings.count;++i)
            {
                sprintf(childbuf,"%s/%s", path, strings.data[i]);
                int zwflag = zoo_wexists(zh, childbuf, zkstatus_watch, "zkstatus", &stat);
                curStatus = stat.pzxid;
                if(initStatus == curStatus)
                {
                    int zgflag=zoo_get(zkhandle, childbuf, 0, buffer1, &bufferlen1, NULL);
                    if(zgflag == ZOK)
                    {
                        traceEvent("监测到新节点加入 ", childbuf, "INFO");
                    }
                 }
             } 
        }
    }
}
void watch_status(char *str)
{
    int flag;
    struct String_vector strings;
    struct Stat stat;
    flag = zoo_wget_children2(zkhandle, str, zkstatus_watch, "status_watch", &strings, &stat);
    if(flag != ZOK)
    {
        traceEvent("zoo_wget_children2 status node faild ", str, "INFO");
    }
}

int check_exists( zhandle_t *zh, const char *path, char *nodeData, int zooNodeType)
{
    int flag;
    char createPath[DATA_LENGTH] = "";
    int pathLen = sizeof(createPath);
    struct Stat stat;
    int existsFlag = zoo_exists(zh, path, 0, &stat);
    if(existsFlag == ZOK)
    {
        return EXISTS;
    }
    else
    {
	flag = zoo_create(zkhandle, path, nodeData, strlen(nodeData), &ZOO_OPEN_ACL_UNSAFE, zooNodeType,/*ZOO_EPHEMERAL|ZOO_SEQUENCE,*/createPath, pathLen);
        if(flag!=ZOK)
        {
			char ermsg[20];
			sprintf(ermsg,"Create node faild erno:%d",flag);
            traceEvent(ermsg, createPath, "ERROR");
            traceEvent("Create node faild ", createPath, "ERROR");
            return FAIL;
        }
        else
        {
            traceEvent("Create node successful", createPath, "INFO");
            return OK;
        }
    }
}

int init_check_zknode(zhandle_t *zkhandle)
{
    int hostfd, myidfd;
    struct sockaddr_in sin;
    struct ifreq ifr;
    int flag;
	char sys_default_conf[]="{\"sys\":{\"log_level\":\"1\",\"log_timer\":\"10\"}}";
	char init_node_path[][128] = {
		"/sys",
		"/policy",
		"/policy_data",
		"/policy_data/trust_list",
		"/policy_data/block_list"};
	int i=0;
	for (i=0;i<sizeof(init_node_path)/128; i++){
		if(0==i)
			flag = check_exists(zkhandle,init_node_path[i],sys_default_conf,0);
		else
			flag = check_exists(zkhandle,init_node_path[i],"",0);
		if(OK==flag)
			traceEvent("Create node successful ",init_node_path[i],"INFO");
		else if(EXISTS==flag)
			traceEvent("Exists node ",init_node_path[i],"INFO");
		else
			traceEvent("Create node failed ",init_node_path[i],"WARN");
		}
    return 1; 
}

int isLeader()
{
    char tmpbuf[DATA_LENGTH] = "";
    FILE *pp = popen(ZOOKEEPER_STATUS, "r");
    if (!pp)
        return -1;
    fread( tmpbuf, sizeof(char), sizeof(tmpbuf),  pp);
    traceEvent("zookeeper run in ", tmpbuf, "INFO");
    pclose(pp);
    if(strstr(tmpbuf, "follower"))
    {
        return 0;
    }
    else if(strstr(tmpbuf, "leader"))
    {
        return 1;
    }
    else
    {
        return 2;
    }
}
static void stop (int sig) 
{
    traceEvent("Catch ctr+c singal ", "", "INFO");
    int i;
    for(i=0;i<myStr.count;i++)
    {
        if(myStr.data[i] != NULL)
            free(myStr.data[i]);
    }
    free(myStr.data);
    zookeeper_close(zkhandle);
    traceEvent("Stop process ", "", "INFO");
    exit(0);
}
void loop_watch_policy()
{
    int num;
    int i, j;
    char newPolicy[DATA_LENGTH] = "";
    int newPolicyLen = sizeof(newPolicy);
    struct Stat curStat;
    struct String_vector curStrings;
    char curPolicy[DATA_LENGTH] = "";
    char curNode[LENGTH] = "";
    int curMzxid, mzxid;
    char delCmd[LENGTH] = "";
    while(loopRun == 1)
    {
        sleep(20);
        num = 0;
        int flag = zoo_get_children2(zkhandle, GROUP_POLICY_ZK, false, &curStrings, &curStat);
        if(flag == ZOK && curStat.cversion != current_version && curStrings.count > myStr.count || flag == ZOK && curStat.cversion != current_version)
        {
            for (i=0;i<curStrings.count;i++)
            {
                int findcount = 0;
                for(j=0;j<myStr.count;j++)
                {
                    if(strcmp(curStrings.data[i], myStr.data[j]))
                    findcount++;
                    if(!strcmp(curStrings.data[i], myStr.data[j]))
                    {
                        int dataLen = sizeof(curPolicy);
                        struct Stat curStat;
                        sprintf(curNode, "%s/%s", GROUP_POLICY_ZK, curStrings.data[i]);
                        zoo_get(zkhandle, curNode, false, curPolicy, &dataLen, &curStat);
                        curMzxid = curStat.mzxid;
                        mzxid = myStr.mzxid[j];
                        if(curMzxid != mzxid)
                        {
                            traceEvent("Get the lost set group policy name ", curStrings.data[i], "INFO");
                            //parsePolicy(curPolicy);
                            myStr.mzxid[j] = curStat.mzxid;
                        }
                    }
                }
                if(findcount == myStr.count )
                {
                    struct mylist tmpStr;
                    char newzkNode[DATA_LENGTH] = "";
                    struct Stat curStat, newStat;
                    sprintf(newzkNode, "%s/%s", GROUP_POLICY_ZK, curStrings.data[i]);
                    num++;
                  //gpj  zoo_wget(zkhandle, newzkNode, zkgroupolicy_watch, "groupolicy_watch", newPolicy, &newPolicyLen, &newStat);
                  //  parsePolicy(newPolicy);
                    traceEvent("Get the lost group policy name ", newzkNode, "INFO");
                    current_version++;
                    tmpStr.count = myStr.count+1;
                    tmpStr.data = (char**)malloc(tmpStr.count * sizeof(char *));
                    memcpy(tmpStr.data, myStr.data, myStr.count*sizeof(char *));
                    memcpy(tmpStr.mzxid, myStr.mzxid, myStr.count);
                    tmpStr.data[tmpStr.count - 1] = strdup(curStrings.data[i]);
                    tmpStr.mzxid[tmpStr.count - 1] = newStat.mzxid;
		            free(myStr.data);
                    myStr = tmpStr;
                }
            }
        }
        if(flag == ZOK && curStat.version != current_version && curStrings.count < myStr.count)
        {
            for(i=0;i<myStr.count;i++)
            {
                int count = 0;
                for (j=0;j<curStrings.count;j++)
                {
                    if(strcmp(myStr.data[i], curStrings.data[j]))
                    {
                        count++;
                    }
                }
                if(count == curStrings.count)
                {
	            int m = 0, n = 0;
                    struct mylist tmpStr;
                    char newzkNode[DATA_LENGTH] = "";
                    char delFile[LENGTH] = "";
                    num++;
                    //sprintf(newzkNode, "/group/policy/%s", myStr.data[i]);
                    sprintf(delFile, "%s/%s", GROUP_POLICY_FILE_DIR, myStr.data[i]);
                    traceEvent("Get the lost delete group policy name ", delFile, "INFO");
                    sprintf(delCmd, "/usr/local/bin/groupparser -D %s", delFile);
                    traceEvent("Delete group policy cmd ",delCmd,"INFO");
                    system(delCmd);
                    remove(delFile);
                    current_version++;
                    if(myStr.data[i] != NULL)
                    {
                        myStr.mzxid[i] = 0;
                        free(myStr.data[i]);
                        myStr.data[i] = NULL;
                    }
                    tmpStr.count = myStr.count - 1;
                    tmpStr.data = (char**)malloc(tmpStr.count * sizeof(char *));		
                    for(n=0;n<myStr.count;n++)
                    {
                        if(myStr.data[n] != NULL && myStr.mzxid[n] != 0)
                        {
                            tmpStr.data[m] = (char *)malloc(strlen(myStr.data[n])+1);
                            memset(tmpStr.data[m], 0, strlen(myStr.data[n])+1);
                            memcpy(tmpStr.data[m], myStr.data[n], strlen(myStr.data[n]));
                            tmpStr.mzxid[m] = myStr.mzxid[n];
                            m++;
                        }
                    }
                    free(myStr.data);
                    myStr = tmpStr;
                }
            }
        }
    }
}
void  init_zk_for_test(zhandle_t* zkhandle)
{
	//init some data for test
	char test_nodes[][512] = {
	//	"/sys",
		"/policy/baidu.com",
		"/policy/letv.com",
		"/policy_data/trust_list/baidu.com/node1",
		"/policy_data/trust_list/letv.com/node1",
		"/policy_data/block_list/baidu.com/node1",
		"/policy_data/block_list/letv.com/node1"
	};
	char test_nodes_value[][1024] = {
	//	"<sys log_level=3 output_time=10/>",
"{\"protect_level\":\"high\",\"threshold_url\":\"1000\",\"threshold_srcip\":\"200\",\"qos\":{\"policy\":[{\"https\":\"false\",\"srcip\":\"1.1.1.1\",\"url\":\"letv.com\",\"each_url\":\"true\",\"each_srcip\":\"false\",\"value\":\"1234\"},{\"https\":\"false\",\"srcip\":\"1.1.1.1\",\"url\":\"letv1.com\",\"each_url\":\"true\",\"each_srcip\":\"false\",\"value\":\"1234\"}]}}",
"{\"protect_level\":\"low\",\"threshold_url\":\"1000\",\"threshold_srcip\":\"200\",\"qos\":{\"policy\":[{\"https\":\"false\",\"srcip\":\"1.1.1.1\",\"url\":\"letv.com\",\"each_url\":\"true\",\"each_srcip\":\"false\",\"value\":\"1234\"},{\"https\":\"false\",\"srcip\":\"1.21.1.1\",\"url\":\"letv1.com\",\"each_url\":\"true\",\"each_srcip\":\"false\",\"value\":\"1234\"}]}}",
"{\"trust_list\":[{\"srcip\":\"1.1.11.1\",\"url\":\"letv.com\"},{\"srcip\":\"1.1.11.1\",\"url\":\"letv22.com\"}]}",
"{\"trust_list\":[{\"srcip\":\"2.1.11.1\",\"url\":\"letv2.com\"},{\"srcip\":\"1.1.11.1\",\"url\":\"letv22.com\"}]}",
"{\"block_list\":[{\"srcip\":\"3.1.11.1\",\"url\":\"letv2.com\"},{\"srcip\":\"1.1.11.1\",\"url\":\"letv22.com\"}]}",
"{\"block_list\":[{\"srcip\":\"4.1.11.1\",\"url\":\"letv2.com\"},{\"srcip\":\"1.1.11.1\",\"url\":\"letv22.com\"}]}"
	};
	int i=0;
	struct Stat sta;
	char createPath[128];
	int pathlen = sizeof(createPath);
	int flag_create;
	char ermsg[128];
	for(i=0;i<sizeof(test_nodes)/512;i++){
		if (ZOK != zoo_exists(zkhandle,test_nodes[i],0,&sta)){
			flag_create = zoo_create(zkhandle,test_nodes[i],test_nodes_value[i],strlen(test_nodes_value[i]),&ZOO_OPEN_ACL_UNSAFE,0,createPath,pathlen);
			if(ZOK!=flag_create){
				sprintf(ermsg,"test create node failed no:%d data_len is %d",flag_create,strlen(test_nodes_value[i]));
				traceEvent(ermsg ,test_nodes[i],"WARN");
			}else{
				traceEvent("test create node success ",test_nodes[i],"INFO");
			}
		}
	}
}

//sys conf watcher
void sys_conf_watch(zhandle_t* zh,int type,int state,const char* path,void* watchCtx)
{
	char info[512];
	sprintf(info,"type:%d state:%d path:%s ",type,state,path);
	traceEvent("sys conf changed ",info,"INFO");
	char sysData[DATA_LENGTH] = "";
	int dataLen = sizeof(sysData);
	if(ZOO_CREATED_EVENT==type){
		traceEvent("Sys conf create event",path,"WARN");
	}else if (ZOO_DELETED_EVENT==type){
		traceEvent("Sys conf create event",path,"WARN");
	}else if (ZOO_CHANGED_EVENT==type){
		char sysData[DATA_LENGTH] = "";
		int dataLen = sizeof(sysData);
		struct Stat stat;
		//set watch get value
		zoo_wget(zh,path,sys_conf_watch,"watch_sys",sysData,&dataLen,&stat);
		traceEvent("Sys conf changed",path,"INFO");
		parse_sys_conf(sysData,strlen(sysData));
		addSys2File(); //sys msg to engine
		outSysConf2File(); //sys msg to local file
	}
}
//do handle sys conf
void handle_sys_conf_data(int rc,const char* value,int value_len,const struct Stat* stat,const void* data)
{
	char msg[DATA_LENGTH];
	char sysdata[DATA_LENGTH];
	sprintf(msg,"rc:%d,value:%s ,value_len:%d, data:%s",rc,value,value_len,data);
	traceEvent("Do handle_sys_conf_data",msg,"INFO");
	memcpy(sysdata,value,value_len);
	//fprintf(stderr,"-------------------data:%s",sysdata);
    parse_sys_conf(sysdata,value_len);
    addSys2File(); //sys msg to engine
    outSysConf2File(); //sys msg to local file
    set_aopt_busy(false);
}
//policy_wather
void policys_conf_watch(zhandle_t* zh,int type,int state,const char* path,void* watchCtx)
{
	//main:watch /policy/* create/delete
	char info[512];
	sprintf(info,"type:%d state:%d path:%s ",type,state,path);
	traceEvent("policy conf changed ",info,"INFO");
	char sysData[DATA_LENGTH] = "";
	int dataLen = sizeof(sysData);
	if(ZOO_CREATED_EVENT==type){
		traceEvent("Policy conf create event",path,"WARN");
	}else if (ZOO_DELETED_EVENT==type){
		traceEvent("Policys conf delete event",path,"WARN");
	}else if (ZOO_CHANGED_EVENT==type){
		// /policy node changed! should not here!
		char sysData[DATA_LENGTH] = "";
		int dataLen = sizeof(sysData);
		struct Stat stat;
		//set watch get value
		zoo_wget(zh,path,policys_conf_watch,"watch_sys",sysData,&dataLen,&stat);
		traceEvent("Policys conf changed ",path,"INFO");
	}else if (ZOO_CHILD_EVENT==type){
		traceEvent("Policys conf child event ",path,"INFO");
		struct String_vector childStrings;
		struct Stat stat;
		zoo_wget_children2(zh,path,policys_conf_watch,watchCtx,&childStrings,&stat);
		int cnt = childStrings.count;
		if(global_conf.domainNum>=cnt){
			//handle add new node only
			traceEvent("Child del event,need not handle return",path,"INFO");
			return;
		}
        traceEvent("Child add event,need handle ",path,"INFO");
        char domain[DOMAIN_LENGTH];
		int i=0;
		for(i=0;i<cnt;i++){
			strcpy(domain,childStrings.data[i]);
			if(NULL==searchDomainNode(domain)){
				//here child event is add new node
                handle_each_policy(childStrings.data[i],true);
				return;
			}
		}
	}
}
//do handle one policy conf
void zkpolicy_watch(zhandle_t* zh,int type,int state,const char* path,void* watherCtx)
{
	//watch: /policy/domain chg 
	//get new conf ,register to watch,parse to conf
    if(ZOO_CREATED_EVENT==type){
		traceEvent("zkpolicy watch create event",path,"INFO");
	}else if(ZOO_DELETED_EVENT==type){
		traceEvent("zkpolicy watch delete event",path,"INFO");
		//TODO: delete the node
		char subPath[DOMAIN_LENGTH];
		strcpy(subPath,path);
		//fprintf(stderr,"changed1---------ptr:%s\n",ptr);
		char* ptr = strtok(subPath,"/");
		ptr = strtok(NULL,"/");
		//fprintf(stderr,"delete node---------ptr:%s\n",ptr);
		//fflush(stderr);
        handle_del_policy(ptr);
	}else if(ZOO_CHANGED_EVENT==type){
       //parse and set policy
		traceEvent("zkpolicy watch changed event",path,"INFO");
		//get domain name from path
		char subPath[DOMAIN_LENGTH];
		strcpy(subPath,path);
		//fprintf(stderr,"changed1---------ptr:%s\n",ptr);
		char* ptr = strtok(subPath,"/");
		ptr = strtok(NULL,"/");
		//fprintf(stderr,"changed2---------ptr:%s\n",ptr);
		//fflush(stderr);
        handle_each_policy(ptr,false); //false: not new node,just changed
	}
}
void initDomainNode(Domain_node* domain_ptr)
{
	memset(domain_ptr->domainName,0,URL_LENGTH);
	//domain_ptr->cc_level = 0;
	memset(domain_ptr->cc_level,0,S_LENGTH);
	domain_ptr->threshold_srcip = 0;
	domain_ptr->threshold_url = 0;
    domain_ptr->enable = true;
	domain_ptr->qos_list = NULL;
	domain_ptr->qos_list_cur = NULL;
	domain_ptr->trust_list = NULL;
	domain_ptr->trust_list_cur = NULL;
	domain_ptr->block_list = NULL;
	domain_ptr->block_list_cur = NULL;
	domain_ptr->pre = NULL;
	domain_ptr->next = NULL;
}

void clear_domain_node(Domain_node* domain_node)
{
	memset(domain_node->domainName,0,DOMAIN_LENGTH);
	memset(domain_node->cc_level,0,S_LENGTH);
	domain_node->threshold_url = 0;
	domain_node->threshold_srcip = 0;
	{
		Qos_node* qos_tmp = domain_node->qos_list;
		Qos_node* qos_del;
		while(qos_tmp){
			qos_del = qos_tmp;
			qos_tmp = qos_tmp->next;
			free(qos_del);
		}
		domain_node->qos_list = NULL;
		domain_node->qos_list_cur = NULL;
	}
	{
		Trust_block_table* trust_tmp = domain_node->trust_list;
		Trust_block_table* trust_del;
		while(trust_tmp){
			trust_del = trust_tmp;
			trust_tmp = trust_tmp->next;
			free(trust_del);
		}
		domain_node->trust_list = NULL;
		domain_node->trust_list_cur = NULL;
	}
	{
		Trust_block_table* block_tmp = domain_node->block_list;
		Trust_block_table* block_del;
		while(block_tmp){
			block_del = block_tmp;
			block_tmp = block_tmp->next;
			free(block_del);
		}
		domain_node->block_list = NULL;
		domain_node->block_list_cur = NULL;
	}
}

Domain_node* searchDomainNode(const char* domainName)
{
	Domain_node* find_node = global_conf.domain_list_cur;
	if(NULL == find_node){
		return NULL;
	}else{
		if(strcmp(domainName,find_node->domainName)==0){
			return find_node;
		}
	}
	find_node = global_conf.domain_list;
    while(find_node){
		if(strcmp(domainName,find_node->domainName)==0){
			return find_node;
		}
		find_node = find_node->next;
	}
	return find_node;
}

void insertDomainList(Domain_node* node)
{
	if(NULL==global_conf.domain_list_cur){
		//first node
		global_conf.domain_list = node;
		global_conf.domain_list_cur = node;
	}else{
		//has nodes already
		global_conf.domain_list_cur->next = node;
		node->pre = global_conf.domain_list_cur;
		global_conf.domain_list_cur = node;
	}
	global_conf.domainNum++;
}

Domain_node* handle_policy_base_conf(const char* domainName,const char* basePath,bool new_flag)
{
    /*
     * new_flag :true new node  false: node changed
     */

	int dataLen = SPACE_1M;
	memset(PolicyBaseData,0,dataLen);
	struct Stat stat;
	int flag = zoo_wget(zkhandle,basePath,zkpolicy_watch,"watch_policy",PolicyBaseData,&dataLen,&stat);
//	fprintf(stderr,"zoo_wget dataLen:%d, PolicyBaseData:%s\n",dataLen,PolicyBaseData);
//	fflush(stderr);
	Domain_node* set_domain_node = NULL;
	if(!new_flag){
		//domain exists: search first,then reset it. 
		set_domain_node = searchDomainNode(domainName);
		if(set_domain_node)
			clear_domain_node(set_domain_node);
	}
	//new_flag or not found ,create and add to Domain_node_list
	if(!set_domain_node){
	    set_domain_node = malloc(sizeof(Domain_node));
		if(!set_domain_node){
			traceEvent("Create Domain node failed","","WARN");
			return NULL;
		}
		initDomainNode(set_domain_node);
		//insert this node to domain list
		insertDomainList(set_domain_node);
	}
	if(0==parse_policy_base_conf(domainName,set_domain_node))
		return set_domain_node;
	else
		return NULL;
}

void handle_policy_trust_conf(const char* domainName,const char* trustPath,Domain_node* setDomainNode)
{
	traceEvent("Handle_trust conf",domainName,"INFO");
	struct String_vector curstrings;
	struct Stat curstat;
	int flag = zoo_get_children2(zkhandle,trustPath,false,&curstrings,&curstat);
	if(ZOK==flag){
		int i=0;
		for(i=0;i<curstrings.count;i++){
			char subPath[128];
			memset(subPath,0,128);
			sprintf(subPath,"%s/%s",trustPath,curstrings.data[i]);
			int trustLen = SPACE_1M;
			memset(PolicyTrustData,0,trustLen);
			int cflag = zoo_get(zkhandle,subPath,0,PolicyTrustData,&trustLen,NULL);
			if(ZOK!=cflag){
				traceEvent("Zoo get trust data failed",subPath,"WARN");
			}else{
				char msg[1024];
				sprintf(msg,"PolicTrustData:%s",PolicyTrustData);
				traceEvent("Got PolicyTrustData ",msg,"INFO");
				parse_policy_trust_list(domainName,setDomainNode);
			}
		}
	}
}
void handle_policy_block_conf(const char* domainName,const char* blockPath,Domain_node* setDomainNode)
{
	struct String_vector curstrings;
	struct Stat curstat;
	int flag = zoo_get_children2(zkhandle,blockPath,false,&curstrings,&curstat);
	if(ZOK==flag){
		int i=0;
		for(i=0;i<curstrings.count;i++){
			char subPath[128];
			memset(subPath,0,128);
			sprintf(subPath,"%s/%s",blockPath,curstrings.data[i]);
//			fprintf(stderr,"g-------ggggggg---subpath:%s,getpath:%s",subPath,curstrings.data[i]);
//			fflush(stderr);
			int blockLen = SPACE_1M; 
			memset(PolicyBlockData,0,blockLen);
			int cflag = zoo_get(zkhandle,subPath,0,PolicyBlockData,&blockLen,NULL);
			if(ZOK!=cflag){
				traceEvent("Zoo get trust data failed",subPath,"WARN");
			}else{
				parse_policy_block_list(domainName,setDomainNode);
			}
		}
	}
}
void handle_each_policy(const char* domain_name,bool new_flag)
{
	/*
     * new_flag-- true: new policy false: node changed
     */

	char basePath[128];
	char trustPath[128];
	char blockPath[128];
	char domainName[128];
	sprintf(basePath,"/policy/%s",domain_name);
	//TODO:maybe has many trust_list nodes,need to join them
	sprintf(trustPath,"/policy_data/trust_list/%s",domain_name);
	sprintf(blockPath,"/policy_data/block_list/%s",domain_name);
	sprintf(domainName,"%s",domain_name);
	int domainLen = strlen(domainName);
	fprintf(stderr,"bpath:%s,tpath:%s,bpath:%s\n",basePath,trustPath,blockPath);
	fflush(stderr);
	Domain_node* set_domain_node = handle_policy_base_conf(domainName,basePath,new_flag);
	if(set_domain_node){
		handle_policy_trust_conf(domainName,trustPath,set_domain_node);
		handle_policy_block_conf(domainName,blockPath,set_domain_node);
	}else{
		traceEvent("Parse base conf fail ,will not parse trust/block list",domainName,"WARN");
	}
    //policyToFile();
    addPolicy2File(set_domain_node);// policy msg to engine	
    outPolicy2File(set_domain_node);// policy msg to local file
}
void outDelConf2File(const char* domainName)
{
    /*
     * del the domain file in local files 
     */
   char* delfile[URL_LENGTH+128];
    strcpy(delfile,CC_CONF_PATH);
    strcat(delfile,domainName);
    if(0!=access(delfile,F_OK)){
        remove(delfile);
    }
}

void handle_del_policy(const char* domainName)
{
	//find node in list
	Domain_node* del_node = searchDomainNode(domainName);
	if(NULL==del_node){
		traceEvent("Del node failed, can not find in list",domainName,"WARN");
	}else{
		traceEvent("Find the node in list",domainName,"INFO");
		//reset list
		if(del_node->pre)
			del_node->pre->next = del_node->next;
		else
			global_conf.domain_list = del_node->next;
		if(del_node->next)
			del_node->next->pre = del_node->pre;
		else
			global_conf.domain_list_cur = del_node->pre;
		global_conf.domainNum--;
		//free the node
		clear_domain_node(del_node);
		free(del_node);
	}
	//output to file
//	OutPutDelDomain2File(domainName);
    outDelConf2File(domainName);
	//tell the engine
    if (tellEngineCommit())
        traceEvent("Tell engine to commit ok!","","INFO");
    else
        traceEvent("Tell engine to commit failed!","","INFO");
}

//do handle policys conf
void handle_policys_conf(int rc,const struct String_vector* strings,const struct Stat* stat,const void* data)
{
	traceEvent("Do handle_policys_conf","handle sub items","INFO");
	int i,flag;
	if(strings){
		for(i=0;i<strings->count;i++){
			handle_each_policy(strings->data[i],true);
		}
	}
	set_aopt_busy(false);
}
void get_parse_conf(zhandle_t* zk)
{
    char sysConf[DATA_LENGTH];
	int  dataLen = sizeof(sysConf);
	set_aopt_busy(true);
    int  flag = zoo_awget(zkhandle,SYS_CONF_PATH,sys_conf_watch,"sys_conf_change",handle_sys_conf_data,"changed");
	if(ZOK!=flag){
		traceEvent("Zoo awget sys conf failed ",SYS_CONF_PATH,"WARN");
		return;
	}
	while(get_aopt_busy()){
		sleep(1);
	}
	//loop parse policy for each domain
	set_aopt_busy(true);
	flag = zoo_awget_children2(zkhandle,DOMAIN_CONF_PATH,policys_conf_watch,"policy_changed",handle_policys_conf,"init_policy");
	if(ZOK!=flag){
		traceEvent("Zoo awget children failed ",DOMAIN_CONF_PATH,"WARN");
		return;
	}
	while(get_aopt_busy()){
		sleep(1);
	}
}

void test_call(int rc,const char* value, int value_len,struct Stat* stat,void* data)
{
	fprintf(stderr,"test---------%s",value);
}

void* watchGetThread() 
{
    int i, j;
    int timeout = 30000;
    //const char *host = "localhost:2181";
    const char *host = "123.59.102.104:2181";
    get_zookeeper_env();
    zoo_set_debug_level(ZOO_LOG_LEVEL_ERROR);
    zkhandle = zookeeper_init(host, main_watcher, timeout, 0, "hello zookeeper.", 0);
    while(!connected) 
    {
        sleep(1);
    }
    if (zkhandle ==NULL)
    {
        traceEvent("When init connecting to zookeeper servers...", "", "ERROR");
        return;
    }
    if(init_check_zknode(zkhandle))
        traceEvent("Check node ", "over", "INFO");
	//for test init zk file
	//init_zk_for_test(zkhandle);
    int zkType = isLeader();
    signal(SIGINT, stop);
	//alloc space for conf 
    PolicyBaseData = malloc(SPACE_1M);
	PolicyTrustData = malloc(SPACE_5M);
	PolicyBlockData = malloc(SPACE_5M);
	//get and parse conf 
	get_parse_conf(zkhandle);
	//outPolicy2File(NULL);
/*
    loop_watch_policy();
	*/
}

int main(int argc, const char *argv[])
{
	traceEvent("Start policyWatch ","good luck""","INFO");
	watchGetThread();
    while(1)
    {
		sleep(5);	
    }
}
