#ifndef trie_h
#define trie_h

#include "arpa/inet.h"
#include "stdio.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DICTIONARY_SIZE 2

typedef struct as_path{
	int *nodes;
}as_path;

typedef struct trie_node{
	int isKey;
	as_path path;//TODO: as_path array in the future
	void * children[DICTIONARY_SIZE];
}trie_node;

trie_node *create_trie_node(){
	trie_node *pNode = (trie_node *)malloc(sizeof(trie_node));
	pNode->isKey = 0;
	pNode->path.nodes = NULL;
	int i;
	for (i=0;i<DICTIONARY_SIZE;++i)
		pNode->children[i] = NULL;
	return pNode;
}

void trie_insert(trie_node *root, char* key, as_path *path){
	if (path==NULL){
		printf("Fail to insert prefix\n");
		return;
	}
	trie_node *node = root;
	char* p = key;
	while (*p){
		if (node->children[*p-'0']==NULL)
			node->children[*p-'0'] = create_trie_node();
		node = node->children[*p-'0'];
		++p;
	}
	node->isKey = 1;
	node->path.nodes = path->nodes;
}

trie_node *trie_search(trie_node *root, char* key){
	printf("%s\n", key);
	clock_t start = clock();
	trie_node *node = root;
	char *p = key;
	while (*p && node){
		node = node->children[*p-'0'];
		++p;
	}
	printf("Searching time is %f seconds\n", ((double)(clock() - start) / CLOCKS_PER_SEC));
	// if (node == NULL) {
	// 	printf("Not Found\n");
	// }
	// else {
	// 	//Done: show as path
	// 	printf("Found! Path is");
	// 	int i;
	// 	for (i=0;i<sizeof(node->path.nodes);++i){
	// 		if (node->path.nodes[i])
	// 			printf(" %d",node->path.nodes[i]);
	// 	}
	// 	printf("\n");
	// 	//
	// }
	return node;
}

void freeTrie(trie_node *location){
	int i;
	for (i=0;i<DICTIONARY_SIZE;++i)
		if (location->children[i])
			freeTrie(location->children[i]);
	free(location->path.nodes);
	free(location);
}

unsigned long slash_to_mask(int slash){
	unsigned long res = 0xffffffff;
	res = (res >> (32-slash)) << (32-slash);
	return res;
}

char *prefix_01(char *prefix){
	int i = 0;
	for (;i < strlen(prefix);++i)
		if (prefix[i]=='/') break;
	prefix[i] = 0;
	char *prefix_01 = (char*)malloc(sizeof(char)*65);
	memset(prefix_01,0,sizeof(char)*65);
	unsigned long ipaddr = ntohl(inet_addr(prefix));
	for (i = 31;i >= 0;--i){
		prefix_01[i] = ((ipaddr>>(31-i)) & 1) + '0';
	}
	// printf("%s\n", prefix_01);
	return prefix_01;
}

char *prefix_slash(char *prefix){
	char *res = (char *)malloc(sizeof(char)*32);
	memset(res, 0, sizeof(char)*32);
	
	int i = 0;
	for (;i < strlen(prefix);++i)
		if (prefix[i]=='/') break;
	int slash = 0;
	for (i = i + 1;i < strlen(prefix);++i) slash += slash * 10 + prefix[i]-'0';

	char *p = prefix_01(prefix);
	for (i = 0;i < slash;++i)
		res[i] = p[i];
	return res;
}

int isIPv4(char *prefix){
	int i;
	for (i=0;i<strlen(prefix);++i){
		if (prefix[i]==':') return 0;
	}
	return 1;
}

trie_node* load_rib(){
	trie_node *root = create_trie_node();
	char buff[1000];
	char filename[256];
	FILE *fd;

	memset(buff,0,1000);
	memset(filename,0,256);
	scanf("%s",filename);
	fd = fopen(filename,"r");

	if (!fd){
		printf("Fail to load file\n");
		return NULL;
	}

	while (!feof(fd)){
		fgets(buff,1000,fd);
		//Done: deal with the line prefix+path
		char prefix[20];
		memset(prefix,0,20);
		as_path path;
		path.nodes = (int *)malloc(sizeof(int)*15);
		int i,j,tmp;
		for (i=0;buff[i]!='\t';++i){}
		memcpy(prefix,buff,i);//now buff[i] = '\t'
		if (!isIPv4(prefix)) break;
		i = i + 1;
		for (tmp=0,j = 0;i<strlen(buff);++i){
			if (buff[i] == ' ' || i == strlen(buff) - 1){
				path.nodes[j] = tmp;
				j++;
				tmp = 0;
			}
			else{
				tmp = tmp * 10 + (buff[i]-'0');
			}
		}
		trie_insert(root,prefix_01(prefix), &path);
		// printf("Insert %s\n", prefix);
	}

	fclose(fd);
	printf("Initialization finished!\n");

	return root;
}

int *flow2path(unsigned long dst_ip, trie_node *root){
	int i,tmp;
	char *key = (char*)malloc(sizeof(char)*33);
	trie_node *res = NULL;
	for (i=0;i<4;++i){
		memset(key,0,32);
		tmp = 32 - (i + 1) * 8;
		//
		for (i = 31;i >= 0;--i)
			key[i] = ((dst_ip>>(31-i)) & 1) + '0';
		res = trie_search(root,key);
		if (res){
			return res->path.nodes;
		}
	}
	return NULL;
}

int terminal_UI(){
	trie_node *root;
	root = load_rib();

	char* command = (char *)malloc(sizeof(char)*1024);
	memset(command,0,sizeof(char)*1024);

	while (1){
		scanf("%s", command);
		if (strcmp(command, "insert") == 0){
			// printf("plz input the prefix u want to insert: ");
			// char *prefix = (char *)malloc(sizeof(char)*50);
			// scanf("%s",prefix);
			// // cb_insert(root, prefix_01(prefix));
			// trie_insert(root, prefix_01(prefix));
			// free(prefix);

			//do nothing
		}
		else if (strcmp(command, "f") == 0 || strcmp(command, "find") == 0){
			printf("plz input the prefix u want to find: ");
			char *prefix = (char *)malloc(sizeof(char)*50);
			scanf("%s",prefix);
			// if (cb_contain(root, prefix_01(prefix))) printf("Yes\n");
			trie_node *p = trie_search(root, prefix_01(prefix));
			if (p){
				printf("Found! Path is");
				int i;
				for (i=0;i<sizeof(p->path.nodes);++i){
					if (p->path.nodes[i])
						printf(" %d",p->path.nodes[i]);
					}
				printf("\n");
			}
			else
				printf("Not found\n");
		}
		else if (strcmp(command, "exit") == 0){
			printf("Byebye\n");
			break;
		}
		else{
			printf("Wrong order!\n");
			continue;
		}
	}

	free(command);

	freeTrie(root);
	return 0;
}

#endif