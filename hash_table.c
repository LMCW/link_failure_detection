#include "hash_table.h"

int hash_table_init(hash_table *h){
	h->count = 0;
	h->size = HASH_TABLE_INIT_SIZE;
	// if (slash <= 12)
	// 	h->size = HASH_TABLE_LARGE_SIZE;
	// h->table = (flow *)malloc(sizeof(flow) * h->size);
	memset(h->table, 0, sizeof(flow) * h->size);
	int i;
	for (i=0;i < h->size;++i)
		h->table[i].isnull = 1;
	return 1;
}

void insert_hash_table(hash_table *h, flow *f){
	unsigned int key = hash(f->src, f->dst, f->src_p, f->dst_p, h->size);
	while(h->table[key].isnull == 0){
		key = (key + 1) % h->size;
	}
	memcpy(&(h->table[key]), f, sizeof(flow));
	h->count += 1;
	return;
}

void show_ht(hash_table *h){
	if (h){
		printf("Count: %d\n", h->count);
		printf("Size: %d\n", h->size);
		printf("First Element: %d\n", h->table[0].isnull);
	}
	else{
		printf("NULL Hash table.\n");
	}
}

int search_hash_table(hash_table *h, unsigned int src_ip, 
	unsigned int dst_ip, unsigned int src_port, unsigned int dst_port){
	int key = hash(src_ip,dst_ip,src_port,dst_port,h->size);
	int i = 0;
	// printf("Key: %d\n", key);
	// show_ht(h);
	while (h->table[key].isnull == 0){
		if (i >= h->count){
			break;
		}
		if (h->table[key].src==src_ip && h->table[key].dst==dst_ip && h->table[key].src_p==src_port && h->table[key].dst_p==dst_port){
			return key;
		}
		key = (key+1) % h->size;
		++i;
	}
	return -1;
}

static inline int hash(unsigned int src_ip, 
	unsigned int dst_ip, unsigned int src_port, unsigned int dst_port, int size){
	//hash function should be related to the hash table size
	// if (size % HASH_TABLE_INIT_SIZE){
	// 	printf("Abnormal size %d\n", size);
	// 	return -1;
	// }
	int p = size;
	int key = ((src_ip % p) + (dst_ip % p) + (src_port % p) + (dst_port % p)) % p;
	return key;
}

void _hash_init(_hash_table *ht){
	ht->size = _HASH_TABLE_INIT_SIZE;
	ht->elem_num = 0;
	// ht->buckets = (Bucket **)malloc(ht->size * sizeof(Bucket *));
	int i;
	for (i = 0;i < _HASH_TABLE_INIT_SIZE;++i){
		ht->buckets[i] = NULL;
	}
	return;
}

int _insert_hash_table(_hash_table *ht, _flow *f){
	int index = _hash(f);
	Bucket *s_bucket = ht->buckets[index];
	Bucket *tmp = s_bucket;
	while (tmp){
		if (flow_equal(tmp->f, f)){
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

Bucket* _search_hash_table(_hash_table *ht, _flow *f){
	int index = _hash(f);
	Bucket *bkt = ht->buckets[index];
	while (bkt){
		if (flow_equal(bkt->f, f)){
			// printf("Flow found.\n");
			return bkt;
		}
		bkt = bkt->next;
	}
	return NULL;
}

int _hash(_flow *f){
	//hash algorithm 1
	return hash(f->src_ip, f->dst_ip, f->src_port, f->dst_port, _HASH_TABLE_INIT_SIZE);

	//TODO: hash algorithm 2

}

int flow_equal(_flow *a, _flow *b){
	if (a->src_ip == b->src_ip &&
		a->dst_ip == b->dst_ip &&
		a->src_port == b->src_port &&
		a->dst_port == b->dst_port){
		return 1;
	}
	return 0;
}










