#include "prefix.h"
#include "pcap.h"

void init_ps(Prefix_set *set){
	memset(set->pfx_set, 0, sizeof(simple_prefix) * MAX_PFX_NUM);
	int i;
	for (i = 0;i < MAX_MONITOR_PATH_NUM;++i){
		set->covered_path_set[i].nodes = NULL;
	}
	memset(set->covered_path_count, 0, sizeof(int) * MAX_MONITOR_PATH_NUM);
	set->count = 0;
	return;
}

void free_ps(Prefix_set *set){
	int i;
	for (i=0;i < MAX_MONITOR_PATH_NUM;++i){
		if (set->covered_path_set[i].nodes){
			free(set->covered_path_set[i].nodes);
			set->covered_path_set[i].nodes = NULL;
		}
	}
	free(set);
}

int add_prefix(Prefix_set *set, char *pfx,  trie_node *rib_root){
	//find pfx in rib, pfx_node.path
	if (set->count == MAX_PFX_NUM){
		printf("Add failed!\n");
		return 0;
	}
	trie_node *pfx_node = trie_search(rib_root, prefix_01(pfx));
	if (pfx_node == NULL){
		return 2;
	}
	//find pfx-path in set, if in, compare the count to the threshold
	int pos = search_path(set->covered_path_set, pfx_node->path);
	if (pos == -1){
		//new path. insert path
		int key = insert_path(set->covered_path_set, pfx_node->path);
		set->covered_path_count[key] = 1;
		set->pfx_set[set->count].ip = pfx_ip(pfx);
		set->pfx_set[set->count].slash = pfx_slash(pfx);
		set->count += 1;
		return 1;
	}
	else{
		//compare 
		if (set->covered_path_count[pos] > PATH_THRESHOLD)
			return 0;
		else{
			//add prefix, count++
			set->covered_path_count[pos] += 1;
			set->pfx_set[set->count].ip = pfx_ip(pfx);
			set->pfx_set[set->count].slash = pfx_slash(pfx);
			set->count += 1;
			return 1;
		}
	}
	return 0;
}

void pcap_to_raw_set(){
	trie_node *rib_root = load_rib();
	simple_prefix sp_set[MAX_PFX_NUM];
	int statistic[MAX_PFX_NUM];
	memset(statistic, 0, sizeof(int) * MAX_PFX_NUM);
	int pfx_count = 0;

	pcap_file_header pfh;
	pcap_header ph;
	void *buff = NULL;
	int readSize = 0;

	char *filename;
	filename = (void *)malloc(100);
	memset(filename,0,100);
	printf("Pcap filename:");
	scanf("%s", filename);
	FILE *fp = fopen(filename, "r");
	if (fp ==NULL){
		fprintf(stderr, "Open file %s error.\n", filename);
		goto ERROR;
	}

	fread(&pfh, sizeof(pcap_file_header), 1, fp);
	buff = (void *)malloc(1514);

	int packet_count = 0;
	for (;!feof(fp);){
		memset(buff,0,1514);
		readSize = fread(&ph, sizeof(pcap_header), 1, fp);
		if (readSize <= 0) break;
		readSize = fread(buff, 1, ph.capture_len, fp);
		if (readSize != ph.capture_len){
			fprintf(stderr, "pcap file parse error.\n");
			goto ERROR;
		}
		ip_header *ih;
		ih = (void *)malloc(20);
		memcpy(ih,buff,20);
		if (ih->ver_hlen != 0x45){
			memcpy(ih, buff + 14, 20);
		}
		unsigned long ip;
		int pos;
		ip = ntohl(ih->dst_ip);
		trie_node *prefix = trie_search(rib_root, ip_key_l(ip));
		if (prefix){
			int slash = slash_key(prefix->pfx_key);
			unsigned int ip_i = ip & slash_to_mask(slash);
			int i, found = 0;
			for (i = 0;i < pfx_count;++i){
				if (sp_set[i].ip == ip_i && sp_set[i].slash == slash){
					statistic[i]++;
					found = 1;
					// printf("Search_depth: %d\n", i);
					
					break;
				}
			}
			if (found == 0){
				// printf("Prefix count: %d Packet count: %d\n", pfx_count, packet_count);
				printf("New prefix NO.%d %u.%u.%u.%u/%d\n", pfx_count,
					ip_i >> 24, (ip_i >> 16) & 0xff, 
					(ip_i >> 8) & 0xff,
					ip_i & 0xff,
					slash);
				sp_set[pfx_count].ip = ip_i;
				sp_set[pfx_count].slash = slash;
				statistic[pfx_count] = 1;
				pfx_count++;
			}
			else{
				// printf("Found %lu.%lu.%lu.%lu/%d\n", ip >> 24, (ip >> 16) & 0xff, 
				// 	(ip >> 8) & 0xff,
				// 	ip & 0xff,
				// 	slash);
			}
		}
		packet_count++;
	}

ERROR:
	if (buff){
		free(buff);
	}
	if (filename){
		free(filename);
	}
	int i;
	FILE *fout = fopen("./trace_caida/prefix_raw.txt","w");
	for (i = 0;i < pfx_count;++i){
		fprintf(fout, "%u.", sp_set[i].ip >> 24);
		fprintf(fout, "%u.", (sp_set[i].ip >> 16) & 0xff);
		fprintf(fout, "%u.", (sp_set[i].ip >> 8) & 0xff);
		fprintf(fout, "%u/", sp_set[i].ip & 0xff);
		fprintf(fout, "%d\n", sp_set[i].slash);
	}
	fclose(fout);
	fclose(fp);
	freeTrie(rib_root);
}

void generate_set(){
	trie_node *rib_root = load_rib();

	Prefix_set *pfx_set = (void *)malloc(sizeof(Prefix_set));
	init_ps(pfx_set);

	FILE *fp = fopen("./trace_caida/prefix_24.txt","r");
	char buff[256], tmpbuff[256];
	memset(buff, 0, 256);
	memset(tmpbuff, 0, 256);

	FILE *fout = fopen("./trace_caida/prefix_trial_1.txt","w");
	int count = 0, i, j, maxx, f_c = 0, rib_not_found = 0;
	for (;!feof(fp);){
		fgets(buff, 256, fp);
		strcpy(tmpbuff, buff);
		buff[strlen(buff) - 1] = 0;
		int a = add_prefix(pfx_set, buff, rib_root);
		if (a == 1){
			count++;
			fprintf(fout, "%s", tmpbuff);
		}
		else if (a == 0){
			f_c++;
			// printf("%s", tmpbuff);
		}
		else{
			rib_not_found++;
		}
	}
	// for (i = 0, maxx = 0;i < MAX_MONITOR_PATH_NUM;++i){
	// 	if (pfx_set->covered_path_count[i] == 0)
	// 		continue;
	// 	else{
	// 		printf("Path:");
	// 		for (j=0;j<15;++j){
	// 			if (pfx_set->covered_path_set[i].nodes[j] == 0)
	// 				break;
	// 			printf(" %d", pfx_set->covered_path_set[i].nodes[j]);
	// 		}
	// 		printf(" Count: %d\n", pfx_set->covered_path_count[i]);
	// 		if (pfx_set->covered_path_count[i] > maxx)
	// 			maxx = pfx_set->covered_path_count[i];
	// 	}
	// }
	printf("Abandon count: %d\n", f_c);
	printf("Rib not found count: %d\n", rib_not_found);
	printf("Set count: %d\n", pfx_set->count);
	printf("Most_pfx_count Path: %d\n", maxx);
	fclose(fout);
	fclose(fp);
	free_ps(pfx_set);
	printf("Total wrote: %d prefixes.\n", count);
	return;
}

int insert_path(as_path *asp_set, as_path path){
	int key = path_hash(path);
	while(asp_set[key].nodes != NULL){
		key = (key + 1) % MAX_MONITOR_PATH_NUM;
	}
	asp_set[key].nodes = (int *)malloc(sizeof(int) * 15);
	memcpy(asp_set[key].nodes, path.nodes, sizeof(int) * 15);
	return key;
}

int search_path(as_path *asp_set, as_path path){
	int key = path_hash(path);
	int tmp = (key - 1) % MAX_MONITOR_PATH_NUM;
	while (asp_set[key].nodes != NULL){
		if (memcmp(asp_set[key].nodes, path.nodes, sizeof(int) * 15) == 0){
			return key;
		}
		if (key == tmp){
			break;
		}
		key = (key + 1) % MAX_MONITOR_PATH_NUM;
	}
	return -1;
}

int pfx_ip(char *pfx){
	int i;
	for (i=0;i < strlen(pfx);++i){
		if (pfx[i] == '/') break;
	}
	i = i - 1;
	char *tmp = (void *)malloc(i+1);
	memset(tmp, 0, i+1);
	memcpy(tmp, pfx, i);
	int ip = ntohl(inet_addr(tmp));
	free(tmp);
	return ip;
}

int pfx_slash(char *pfx){
	int i, slash = 0;
	for (i=0;i < strlen(pfx);++i){
		if (pfx[i] == '/') break;
	}
	i = i + 1;
	for (;i < strlen(pfx);++i)
		slash = slash * 10 + (pfx[i] - '0');
	return slash;
}

int path_hash(as_path asp){
	int key = 0, i;
	for (i = 0;i < 15;++i){
		if (asp.nodes[i])
			key = (key + asp.nodes[i]) % MAX_MONITOR_PATH_NUM;
		else
			break;
	}
	return key;
}