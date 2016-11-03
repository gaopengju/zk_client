#ifndef _UTILITY_H_
#define _UTILITY_H_
typedef unsigned int u_int;
extern char *replace(char * src,char oldChar,char newChar);
extern void stringtrim(char *str);
extern void cleanFile(char *path);
extern void traceEvent(char *content, const char *name, char *type);
#endif
