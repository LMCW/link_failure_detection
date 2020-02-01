#ifndef HASH_TABLE
#define HASH_TABLE

#define HASH_TABLE_INIT_SIZE 29989

typedef struct flow{
	int isnull;
	unsigned int src;
	unsigned int dst;
	unsigned int src_p;
	unsigned int dst_p;
	unsigned int expect_seq;
	unsigned int curr_ack;
	unsigned int last_size;
}flow;

typedef struct hash_table{
	int count;
	int size;
	flow table[HASH_TABLE_INIT_SIZE];
}hash_table;

int hash_table_init(hash_table *h);
void insert_hash_table(hash_table *h, flow *f);
int search_hash_table(hash_table *h, unsigned int src_ip, 
	unsigned int dst_ip, unsigned int src_port, unsigned int dst_port);
int hash(unsigned int src_ip, 
	unsigned int dst_ip, unsigned int src_port, unsigned int dst_port, int size);

#endif