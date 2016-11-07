#ifndef _PARSE_H_
#define _PARSE_H_

#define IP_LENGTH        16

#include <libxml/xpath.h>
extern char macIp[IP_LENGTH];
extern char injectIp[IP_LENGTH];
extern char injectMask[IP_LENGTH];
extern char interfaceIp[IP_LENGTH];
extern int globalOutLimit;
//extern char clusterInfo[512][512];

extern void parseMac(char *pMsg);
extern void parseInject(const char *pMsg);
extern void parseInterface(char *pMsg);
extern void parseGlobalPolicy(char *pMsg);
extern void parse_sys_conf(const char* data,size_t len);


//gpj

void parseDomainPolicy(const char* urlName,size_t nameLen,const char* baseData,size_t baseLen,const char* trustData,size_t trustLen,const char* blockData,size_t blockLen,bool addFlag);
xmlXPathObjectPtr getNodeset(xmlDocPtr doc, const xmlChar *xpath); 
#endif

