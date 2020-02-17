#ifndef HASH_TABLE
#define HASH_TABLE

#include "rtt.h"
#include "flow.h"
#include "string.h"
#include "stdlib.h"
#include "stdio.h"
// #define HASH_TABLE_INIT_SIZE 29989
#define _HASH_TABLE_INIT_SIZE 9973

#define HASH_TABLE_INIT_SIZE 99991
// #define HASH_TABLE_LARGE_SIZE 99991
#define EXIST 0
#define INSERT_SUCC 1
#define INSERT_FAIL -1

typedef struct timestamp{
	unsigned int timestamp_s;
	unsigned int timestamp_ms;	
}timestamp;

typedef struct flow{
	int isnull;
	unsigned int src;
	unsigned int dst;
	unsigned int src_p;
	unsigned int dst_p;
	unsigned int expect_seq;
	unsigned int curr_ack;
	timestamp last_ts;
	rtt_distribution rd;
}flow;

//TODO: Change the data structure of hashtable

typedef struct hash_table{
	int count;
	int size;
	flow table[HASH_TABLE_INIT_SIZE];
}hash_table;

int hash_table_init(hash_table *h);
void insert_hash_table(hash_table *h, flow *f);
int search_hash_table(hash_table *h, unsigned int src_ip, 
	unsigned int dst_ip, unsigned int src_port, unsigned int dst_port);
static inline int hash(unsigned int src_ip, 
	unsigned int dst_ip, unsigned int src_port, unsigned int dst_port, int size);

typedef struct Bucket{
	_flow *f;
	struct Bucket *next;
}Bucket;

typedef struct _hash_table{
	int size;
	int elem_num;
	Bucket* buckets[_HASH_TABLE_INIT_SIZE];
}_hash_table;

void _hash_init(_hash_table *ht);
int _insert_hash_table(_hash_table *ht, _flow *f);
Bucket* _search_hash_table(_hash_table *ht, _flow *f);
int _hash(_flow *f);

int flow_equal(_flow *a, _flow *b);
#endif