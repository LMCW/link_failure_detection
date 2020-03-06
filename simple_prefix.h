#ifndef simple_prefix_h
#define simple_prefix_h

#include "trie.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MAX_PFX_NUM 500000
#define MAX_MONITOR_PATH_NUM 199999 //TODO: determine the exact number according to the rib file
#define PATH_THRESHOLD 100

typedef struct simple_prefix{
	unsigned int ip;
	int slash;
}simple_prefix;

typedef struct Prefix_set{
	simple_prefix pfx_set[MAX_PFX_NUM];
	as_path covered_path_set[MAX_MONITOR_PATH_NUM]; //hash table to store as paths
	int covered_path_count[MAX_MONITOR_PATH_NUM];
	int count;
}Prefix_set;

void init_ps(Prefix_set *set);//Initialization of the prefix set

void free_ps(Prefix_set *set);//free memory of the prefix set

int add_prefix(Prefix_set *set, char *pfx, trie_node *rib_root); /* if a path to the prefix is new to the set, 
																			* add the prefix to the set.
																			* A path is new means path occurrence count 
																			* is no more some threshold. 
																			*/

// void generate_set();

void pcap_to_raw_set(char const *pcap_file, char const *as_rel_file, char const *rib_file, char const *output);

int pfx_ip(char *pfx);

int pfx_slash(char *pfx);

int insert_path(as_path *asp_set, as_path path);

int search_path(as_path *asp_set, as_path path);

int path_hash(as_path asp); //hash function

#endif