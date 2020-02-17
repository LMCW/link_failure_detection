#ifndef measure_h
#define measure_h

#include "pcap.h"
#include "flow.h"
#include "hash_table.h"

typedef struct _prefix{
	unsigned long ip;
	int slash;
	int threshold;
	_hash_table *ht;

}_prefix;

int pfx_file_size(char *filename);
_prefix *_pfx_set_from_file(char *filename, int size);

int _ip_pfx_match(unsigned long ip, _prefix pfx);
int _binary_search_ip(unsigned long ip, _prefix *pfx_set, int set_size);
int _pfx_cmp(const void *a, const void *b);

void rtt_measure();

#endif