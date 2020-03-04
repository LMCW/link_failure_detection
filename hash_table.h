#ifndef hash_table_h
#define hash_table_h

#include "timestamp.h"
#include "flow.h"

#define HASH_TABLE_INIT_SIZE 9973
#define EXIST 0
#define INSERT_SUCC 1
#define INSERT_FAIL -1

typedef struct Bucket{
	flow *f;
	struct Bucket *next;
}Bucket;

typedef struct hash_table{
	int size;
	int elem_num;
	Bucket* buckets[HASH_TABLE_INIT_SIZE]; 
}hash_table;

void hash_init(hash_table *ht);
int insert_ht(hash_table *ht, flow *f);
Bucket *search_ht(hash_table *ht, flow *f);
static inline int hash(flow *f);

int flow_equal(flow a, flow b);

#endif