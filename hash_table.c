#include "hash_table.h"
#include "stdlib.h"

void hash_init(hash_table *ht){
	ht->size = HASH_TABLE_INIT_SIZE;
	ht->elem_num = 0;
	int i;
	for (i = 0;i < HASH_TABLE_INIT_SIZE;++i)
		ht->buckets[i] = NULL;
	return;
}

int insert_ht(hash_table *ht, flow *f){
	int index = hash(f);
	Bucket *s_bucket = ht->buckets[index];
	Bucket *tmp = s_bucket;
	while (tmp){
		if (flow_equal(*(tmp->f), *f)){
			printf("Already exist!\n");
			return EXIST;
		}
		tmp = tmp->next;
	}
	Bucket *bkt = (Bucket *)malloc(sizeof(Bucket));
	bkt->f = f;
	bkt->next = NULL;
	ht->elem_num += 1;

	if (s_bucket != NULL)
		bkt->next = s_bucket;
	ht->buckets[index] = bkt;
	// printf("Insert Success.\n");
	return INSERT_SUCC;
}


Bucket *search_ht(hash_table *ht, flow *f){
	int index = hash(f);
	Bucket *bkt = ht->buckets[index];
	while (bkt){
		if (flow_equal(*(bkt->f), *f)){
			// printf("Flow found.\n");
			return bkt;
		}
		bkt = bkt->next;
	}
	return NULL;
}

static inline int hash(flow *f){
	int p = HASH_TABLE_INIT_SIZE;
	int key = ((f->src_ip) % p + (f->dst_ip) % p + (f->src_port) % p + (f->dst_port) % p) % p;
	return key;
}

int flow_equal(flow a, flow b){
	if (a.src_ip == b.src_ip &&
		a.dst_ip == b.dst_ip &&
		a.src_port == b.src_port &&
		a.dst_port == b.dst_port){
		return 1;
	}
	else
		return 0;
}
