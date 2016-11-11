#gcc policyWatcher.c parse.c cJSON.c utility.c -I /usr/local/include/zookeeper/ /usr/include/libxml2/ /usr/local/lib/libzookeeper_mt.so /usr/lib64/libxml2.so -lm -w -o aa
objects= policyWatcher.o parse.o cJSON.o utility.o
flags= -I /usr/local/include/zookeeper/ /usr/local/lib/libzookeeper_mt.so  -lm -w -g 
policyWatcher:$(objects) 
	#gcc $(objects) -I /usr/local/include/zookeeper/ /usr/include/libxml2/ /usr/local/lib/libzookeeper_mt.so /usr/lib64/libxml2.so -lm -w -o policyWatch
	gcc $(objects) $(flags) -o policyWatcher
policyWatch.o:policyWatcher.c policyWatch.h
	gcc $(flags) -c policyWatch.c  
parse.o:parse.c parse.h 
	gcc $(flags) -c parse.c
cJSON.o:cJSON.c cJSON.h
	gcc $(flags) -c cJSON.c
utility.o:utility.c utility.h
	gcc $(flags) -c utility.c
