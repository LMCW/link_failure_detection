#include "trie.h"

int binarysearch(int *arr, int target, int count){
	int hi,lo,mid;
	for (lo = 0, hi = count - 1;lo <= hi;){
		mid = (lo + hi) / 2;
		if (arr[mid] < target)
			lo = mid + 1;
		else if (arr[mid] > target)
			hi = mid - 1;
		else
			return mid;
	}
	return -1;
}

as_rel *load_asr(char const *filename){
	char buff[1000];
	// char filename[256];
	// char *filename = "/Users/chenzp/Documents/Research/link_failure_detection/as-rel/20130501.as-rel.txt";
	FILE *fd;

	memset(buff,0,1000);
	// memset(filename,0,256);
	// printf("Plz input the filename of as relationship: ");
	// scanf("%s",filename);
	fd = fopen(filename,"r");

	as_rel *asr = (as_rel *)malloc(sizeof(as_rel));
	int i = 0;
	while(!feof(fd)){
		fgets(buff, 1000, fd);
		if (buff[0]<'0'||buff[0]>'9') {
			continue;//invalid line
		}
		int j,tmp,p;
		for (j = 0,tmp = 0,p = 0;j < strlen(buff);++j){
			if (p == 2){
				if (buff[j]=='-'){
					asr->rel[i] = -1;
				}
				else if (buff[j]=='0'){
					asr->rel[i] = 0;
				}
				else if (buff[j]=='1'){
					asr->rel[i] = 1;
				}
				break;
			}
			if (buff[j]=='|'){
				if (p==0) {
					asr->a[i]=tmp;
					tmp = 0;
				}
				else if (p==1) {
					asr->b[i]=tmp;
					tmp = 0;
				}
				p += 1;
			}
			tmp = tmp * 10 + (buff[j]-'0');
		}
		i += 1;
	}
	asr->count = i;

	fclose(fd);
	// printf("Finish loading AS relation list!\n");
	// printf("The first line is %d|%d|%hd\n", asr->a[0], asr->b[0], asr->rel[0]);

	return asr;
}

int path_cmp(as_path path1, as_path path2, int local_as, int mode, as_rel *asr){
	if (path1.nodes == NULL) return 1;
	if (path2.nodes == NULL) return -1;
	if (mode == 0){
		short rel1 = 1, rel2 = 1;
		int left, right, tmp, i;
		tmp = asr->rel[binarysearch(asr->a, local_as, asr->count)];
		if (tmp == 0) return 0;
		for(left=tmp;asr->a[left]!=local_as;left--){}
		left += 1;
		for (right=tmp;asr->a[right]!=local_as;right++){}
		right -= 1;
		for (i = left;i <= right;++i){
			if (asr->b[i]==path1.nodes[0]) 
				rel1 = asr->rel[i];
			if (asr->b[i]==path2.nodes[0])
				rel2 = asr->rel[i];
		}
		if (rel1 < rel2) return -1;
		else if (rel1 > rel2) return 1;
		else return 0;
	}
	else if (mode == 1){
		int len1,len2,i;
		for (i=0,len1=0,len2=0;i < 15;++i){
			if (path1.nodes[i]) len1++;
			if (path2.nodes[i]) len2++;
		}
		if (len1 < len2) return -1;
		else if (len1 > len2) return 1;
		else return 0;
	}
	return 0;
}

trie_node *create_trie_node(){
	trie_node *pNode = (trie_node *)malloc(sizeof(trie_node));
	pNode->isKey = 0;
	memset(pNode->pfx_key, 0, 33);
	pNode->path.nodes = NULL;
	int i;
	for (i=0;i<DICTIONARY_SIZE;++i)
		pNode->children[i] = NULL;
	return pNode;
}

void trie_insert(trie_node *root, char* key, as_path *path, as_rel *asr){
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
	if (node->isKey == 0){
		node->isKey = 1;
		strcpy(node->pfx_key, key);
		node->path.nodes = path->nodes;
	}
	// if (path_cmp(node->path, *path, 12085, 1,asr) > 0){
	// 	node->path.nodes = path->nodes;
	// }
	// printf("Insert Succeed! %s.\n", key);
}

trie_node *trie_search(trie_node *root, char* key){
	// printf("%s\n", key);
	// clock_t start = clock();
	trie_node *node = root;
	trie_node *tmp = NULL;
	char *p = key;

	while (*p && node){
		if (node->isKey){
			tmp = node;
		}
		node = node->children[*p-'0'];
		++p;
	}
	// printf("Searching time is %f seconds\n", ((double)(clock() - start) / CLOCKS_PER_SEC));
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
	return tmp;
}

void freeTrie(trie_node *location){
	int i;
	for (i=0;i<DICTIONARY_SIZE;++i)
		if (location->children[i])
			freeTrie(location->children[i]);
	// free(location->path.nodes);
	free(location);
}

unsigned long slash_to_mask(int slash){
	unsigned long res = 0xffffffff;
	res = (res >> (32-slash)) << (32-slash);
	return res;
}

char *prefix_01(char *prefix){
	int i = 0;
	int lenp = strlen(prefix);
	for (;i < lenp;++i)
		if (prefix[i]=='/') break;
	prefix[i] = 0;
	int slash = 0;
	for (i = i + 1;i < lenp;++i){
		if (prefix[i] == '\n'){
			break;
		}
		slash = slash * 10 + (prefix[i]-'0');
	}
	char *prefix_01 = (char*)malloc(sizeof(char)*33);
	memset(prefix_01,0,sizeof(char)*33);
	unsigned long ipaddr = ntohl(inet_addr(prefix));
	for (i = slash - 1;i >= 0;--i){
		prefix_01[i] = ((ipaddr>>(31-i)) & 1) + '0';
	}
	// printf("%s\n", prefix_01);
	return prefix_01;
}

char *ip_key_c(char *ip){
	unsigned long ipaddr = ntohl(inet_addr(ip));
	char *key = (char*)malloc(sizeof(char)*65);
	memset(key,0,sizeof(char)*65);
	int i;
	for (i=31;i >= 0;--i){
		key[i] = ((ipaddr>>(31-i)) & 1) + '0';
	}
	return key;
}

char *ip_key_l(unsigned long ip){
	char *key = (void *)malloc(65);
	memset(key,0,sizeof(char)*65);
	int i;
	for (i = 31;i >= 0;--i){
		key[i] = ((ip>>(31-i)) & 1) + '0';
	}
	return key;
}

unsigned int key_ip(char *key){
	int i;
	int len = strlen(key);
	int buff[33];
	memset(buff, 0, sizeof(int) * 33);
	for (i = 0;i < len;++i){
		buff[i] = key[i] - '0';
	}
	unsigned int res = buff[0];
	for (i = 1;i < 32;++i)
		res = (res << 1) + buff[i];
	return res;
}

int slash_key(char *key){
	int len = strlen(key);
	return len;
}

char *prefix_slash(char *prefix){
	char *res = (char *)malloc(sizeof(char)*32);
	memset(res, 0, sizeof(char)*32);
	
	int i = 0;
	for (;i < strlen(prefix);++i)
		if (prefix[i]=='/') break;
	int slash = 0;
	for (i = i + 1;i < strlen(prefix);++i) slash = slash * 10 + prefix[i]-'0';

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

trie_node* load_rib(char const *as_rel_file, char const *rib_file){
	as_rel *asr;
	asr = load_asr(as_rel_file);

	trie_node *root = create_trie_node();
	char buff[1000];
	// char filename[256];
	// char *filename = "/Users/chenzp/Documents/Research/link_failure_detection/ribs/2015/dedup_sreqix_201502191200.txt";
	FILE *fd;

	memset(buff,0,1000);
	// memset(filename,0,256);
	// printf("Plz input the filename of rib: ");
	// scanf("%s",filename);
	fd = fopen(rib_file,"r");


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
		memset(path.nodes, 0, sizeof(int)*15);
		int i,j,tmp;
		for (i=0;buff[i]!='\t';++i){}
		memcpy(prefix,buff,i);//now buff[i] = '\t'
		if (!isIPv4(prefix)) break;//TODO?: ipv6 expansion
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
		trie_insert(root, prefix_01(prefix), &path, asr);
		// printf("Insert %s\n", prefix);
	}

	fclose(fd);
	// printf("Initialization finished!\n");

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
	// trie_node *root;
	// root = load_rib();

	// char* command = (char *)malloc(sizeof(char)*1024);
	// memset(command,0,sizeof(char)*1024);

	// while (1){
	// 	scanf("%s", command);
	// 	if (strcmp(command, "ip") == 0){
	// 		// printf("plz input the prefix u want to insert: ");
	// 		// char *prefix = (char *)malloc(sizeof(char)*50);
	// 		// scanf("%s",prefix);
	// 		// // cb_insert(root, prefix_01(prefix));
	// 		// trie_insert(root, prefix_01(prefix));
	// 		// free(prefix);
	// 		printf("plz input the prefix u want to find: ");
	// 		char *ip = (char *)malloc(sizeof(char)*30);
	// 		memset(ip, 0, 30);
	// 		scanf("%s", ip);
	// 		trie_node *p = trie_search(root, ip_key_c(ip));
	// 		if (p){
	// 			printf("Found! Path is");
	// 			int i;
	// 			for (i=0;i < 15;++i){
	// 				if (p->path.nodes[i] != 0)
	// 					printf(" %d",p->path.nodes[i]);
	// 				}
	// 			printf("\n");
	// 		}
	// 		else
	// 			printf("Not found\n");
	// 		free(ip);
			
	// 	}
	// 	else if (strcmp(command, "f") == 0 || strcmp(command, "find") == 0){
	// 		printf("plz input the prefix u want to find: ");
	// 		char *prefix = (char *)malloc(sizeof(char)*50);
	// 		scanf("%s",prefix);
	// 		// if (cb_contain(root, prefix_01(prefix))) printf("Yes\n");
	// 		trie_node *p = trie_search(root, prefix_01(prefix));
	// 		if (p){
	// 			printf("Found! Path is");
	// 			int i;
	// 			for (i=0;i < 15;++i){
	// 				if (p->path.nodes[i] != 0)
	// 					printf(" %d",p->path.nodes[i]);
	// 				}
	// 			printf("\n");
	// 		}
	// 		else
	// 			printf("Not found\n");
	// 		free(prefix);
	// 	}
	// 	else if (strcmp(command, "exit") == 0){
	// 		printf("Byebye\n");
	// 		break;
	// 	}
	// 	else{
	// 		printf("Wrong order!\n");
	// 		continue;
	// 	}
	// }

	// free(command);

	// freeTrie(root);
	return 0;
}