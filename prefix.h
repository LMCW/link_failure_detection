#ifndef prefix_h
#define prefix_h

#include "pcap.h"
#include "monitor.h"

#define BIN_NUM 10
#define BIN_TIME 0.08

typedef struct prefix{
	int ip;
	int slash;
}prefix;

typedef struct prefix_set{
	int *statistic;
	int *ip_set;
	int *slash_set; 
	int count;
	int size;
}prefix_set;

int init(prefix_set *S, int Num);
int findPrefix(prefix_set *S, int ip, int slash);
int newPrefix(prefix_set *S, int ip, int slash);
int generateSet(prefix_set *S, int slash);
int showSet(prefix_set *S);
int set2file(prefix_set *S, int threshold);
int setfree(prefix_set *S);

#endif