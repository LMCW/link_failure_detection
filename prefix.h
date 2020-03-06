#ifndef prefix_h
#define prefix_h

#include "hash_table.h"
#include "fifo_queue.h"
#include "timestamp.h"
#include "stdio.h"

#define BIN_NUM 10
#define BIN_TIME 0.08
#define BASIC_THRESHOLD 0

typedef struct prefix{
	unsigned long ip;
	int slash;
	
	// int threshold;
	float thresh_p;
	
	//TODO: Sliding window definition
	int *sliding_window;
	int curr_sw_pos;
	timestamp current_bin_start_time;

	//active flow count, at the same pace with retransmission sliding window
	// int *active_flow_count_window;

	hash_table *ht;

}prefix;

int pfx_file_size(char const *filename);
prefix *pfx_set_from_file(char const *filename, int set_size);
int ip_pfx_match(unsigned long ip, prefix pfx);
int binary_search_ip(unsigned long ip, prefix *pfx_set, int set_size);
int pfx_cmp(const void *a, const void *b);

float update_sw(prefix *pfx, timestamp packet_time, timestamp bin, FILE *fp);
#endif