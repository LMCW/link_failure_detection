#ifndef trie_h
#define trie_h

#include "arpa/inet.h"
#include "stdio.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define AS_REL_SET_NUM 150000
#define DICTIONARY_SIZE 2

typedef struct as_path{
	int *nodes;
}as_path;

typedef struct trie_node{
	int isKey;
	char pfx_key[33];
	as_path path;//TODO: as_path array in the future
	void * children[DICTIONARY_SIZE];
}trie_node;

typedef struct as_rel{
	int a[AS_REL_SET_NUM];
	int b[AS_REL_SET_NUM];
	short rel[AS_REL_SET_NUM];
	int count;
}as_rel;

int binarysearch(int *arr, int target, int count);
as_rel *load_asr(char const *filename);
int path_cmp(as_path path1, as_path path2, int local_as, int mode, as_rel *asr);
trie_node *create_trie_node();
void trie_insert(trie_node *root, char* key, as_path *path, as_rel *asr);
trie_node *trie_search(trie_node *root, char* key);
void freeTrie(trie_node *location);
unsigned long slash_to_mask(int slash);
char *ip_key_c(char *ip);
char *ip_key_l(unsigned long ip);
unsigned int key_ip(char *key);
int slash_key(char *key);
char *prefix_01(char *prefix);
char *prefix_slash(char *prefix);
int isIPv4(char *prefix);
trie_node* load_rib(char const *as_rel_file, char const *rib_file);
int *flow2path(unsigned long dst_ip, trie_node *root);
int terminal_UI();

#endif