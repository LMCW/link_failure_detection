#include "pcap.h"
#include "trie.h"

void prinfPcapFileHeader(pcap_file_header *pfh){
	if (pfh == NULL) return;
	printf("===============\n"
		"magic:0x%0x\n"
		"version_major:%u\n"
		"version_minor:%u\n"
		"thiszone:%d\n"
		"sigfigs:%u\n"
		"snaplen:%u\n"
		"linktype:%u\n"
		"===============\n",
		pfh->magic,
		pfh->version_major,
		pfh->version_minor,
		pfh->thiszone,
		pfh->sigfigs,
		pfh->snaplen,
		pfh->linktype);
	return;
}

void printfPcapHeader(pcap_header *ph){
	if (ph==NULL) return;
	printf("===============\n"
		"ts.timestamp_s:%u\n"
		"ts.timestamp_ms:%u\n"
		"capture_len:%u\n"
		"len:%d\n"
		"===============\n",
		ph->ts.timestamp_s,
		ph->ts.timestamp_ms,
		ph->capture_len,
		ph->len);
	return;
}

unsigned long get_dst_ip(void *data){
	ip_header *ih = NULL;
	ih = (ip_header *)malloc(20);
	memcpy(ih, data, 20);
	if (ih->ver_hlen != 0x45)
		memcpy(ih, data + ETH_LENGTH, 20);
	return (unsigned long)ih->dst_ip;
}

int flow_match(bpf_u_int32 src, bpf_u_int32 dst, bpf_u_int32 src_p, bpf_u_int32 dst_p, flow f){
	// printf("Cmp: src:%u dst:%u <===> flow src:%u dst:%u\n", src, dst, f.src, f.dst);
	if (ntohl(src) == f.src && ntohl(dst) == f.dst && src_p == f.src_p && dst_p == f.dst_p){
		return 1;
	}
	else
		return 0;
}

prefix *pfx_set_from_file(int size){
	prefix *set = (prefix *)malloc(sizeof(prefix)*size);
	memset(set,0,sizeof(prefix)*size);
	char *filename = (void *)malloc(256);
	printf("Prefix filename: ");
	scanf("%s",filename);
	FILE *fp = fopen(filename, "r");
	char *buff = (void *)malloc(1000);
	memset(buff,0,1000);

	int i;
	for (i=0;i < size;++i){
		//initialization of each prefix
		if (feof(fp)) break;
		fgets(buff, 1000, fp);
		int j = 0, len;
		len = strlen(buff);
		for (;j < len;++j)
			if (buff[j]=='/') break;
		buff[j]=0;
		set[i].ip = ntohl(inet_addr(buff));
		set[i].slash = 0;
		for (j=j+1;j < len - 1; ++j){
			set[i].slash = set[i].slash * 10 + (buff[j]-'0');
		}		
		set[i].sliding_window = (int *)malloc(sizeof(int) * BIN_NUM);
		memset(set[i].sliding_window, 0, sizeof(int) * BIN_NUM);
		set[i].curr_sw_pos = 0;
		set[i].current_bin_start_time.timestamp_s = 0;
		set[i].current_bin_start_time.timestamp_ms = 0;
		set[i].ht = (void *)malloc(sizeof(hash_table));
		hash_table_init(set[i].ht);
	}

	free(filename);
	free(buff);

	qsort(set, size, sizeof(prefix), pfx_cmp);
	// for (i=0;i<size;++i){
	// 	printf("%lu.%lu.%lu.%lu/%d\n", set[i].ip >> 24,
	// 		(set[i].ip >> 16) & 0xff,
	// 		(set[i].ip >> 8) & 0xff,
	// 		set[i].ip & 0xff,
	// 		set[i].slash);
	// }
	return set;
}

int pfx_cmp(const void *a, const void *b){
	if (((prefix *)a)->ip < ((prefix *)b)->ip)
		return -1;
	else if (((prefix *)a)->ip == ((prefix *)b)->ip)
		return 0;
	else
		return 1;
}

int ip_pfx_match(unsigned long ip, prefix pfx){
	//return number: 1 means match, 0 means unmatch
	int i;
	unsigned long mask = 0;
	mask = slash_to_mask(pfx.slash);
	ip = ip & mask;
	if (ip==pfx.ip) 
		return 0;
	else if (ip < pfx.ip)
		return -1;
	else
		return 1;
}

int binary_search_ip(unsigned long ip, prefix *pfx_set, int set_size){
	int hi,lo,mid,tmp;
	for (lo=0,hi=set_size-1;lo<=hi;){
		mid = (lo+hi)/2;
		tmp = ip_pfx_match(ip, pfx_set[mid]);
		if (tmp == 1)
			lo = mid + 1;
		else if (tmp == -1)
			hi = mid - 1;
		else{
			// printf("Found %lu index:%d\n", ip, mid);
			return mid;
		}
	}

	return -1;
}

void monitor(){
	//link failure detection
	//load pcap
	pcap_file_header pfh;
	pcap_header ph;

	int count = 0;
	void *buff = NULL;
	int readSize = 0;
	int ret = 0;

	char *filename;
	filename = (void *)malloc(100);
	memset(filename,0,100);
	printf("Pcap filename:");
	scanf("%s", filename);
	FILE *fp = fopen(filename, "r");

	time_t start, end;
	

	timestamp bin;
	bin.timestamp_s = 0;
	bin.timestamp_ms = 80000;

	if (fp == NULL){
		fprintf(stderr, "Open file %s error.\n", filename);
		goto ERROR;
	}

	//prefix set definition or from file
	int set_size = 2720;
	prefix *pfx_set = pfx_set_from_file(set_size); //TODO: determine the count of prefixes to monitor
	printf("Finish prefix file loading!\n");
	//pcap file header
	fread(&pfh, sizeof(pcap_file_header), 1, fp);
	prinfPcapFileHeader(&pfh);

	buff = (void *)malloc(MAX_ETH_FRAME);
	if (buff == NULL){
		fprintf(stderr, "malloc buffer failed.\n");
		goto ERROR;
	}
	int rt_count = 0;
	int tcp_count = 0;
	int total_count = 0;

	int expand_count = 0;
	start = time(NULL);
	//monitoring pcap file
	for (count=1;;++count){
		//get packet from file
		memset(buff,0,MAX_ETH_FRAME);
		readSize = fread(&ph, sizeof(pcap_header),1,fp);
		if (readSize <= 0) 
			break;
		readSize = fread(buff, 1, ph.capture_len, fp);//what is the difference between the two order?
		if (readSize != ph.capture_len){
			fprintf(stderr, "pcap file parse error.\n");
			goto ERROR;
		}

		/*	packet parse
			packet destination ip address
			belong to which prefix: binary search dstip pfxset
			belong to which flow
		*/
		ip_header *ih = (ip_header *)malloc(20);
		int curr_buff_pos = 0;
		memcpy(ih, buff, 20);
		if (ih->ver_hlen != 0x45){
			curr_buff_pos += ETH_LENGTH;
			memcpy(ih, buff + ETH_LENGTH, 20);
		}
		unsigned long dst_ip = ntohl((unsigned long)ih->dst_ip);
		int pfx_index = binary_search_ip(dst_ip, pfx_set, set_size);
		if (pfx_index == -1) {
			free(ih);
			continue;//not belong to the prefixes to monitor
		}
		else{
		}
		total_count++;
		if (ih->protocol == 6){//tcp packet;
			tcp_count++;
			tcp_header *th = (tcp_header *)malloc(20);
			int ih_len = (ih->ver_hlen & 0xf) << 2;
			memcpy(th, buff + ih_len + curr_buff_pos, 20);
			if ((th->flags & 0x10) == 0 || (th->flags & 0x1) != 0){
				free(th);
				free(ih);
				continue;
			}
			int tcp_hlen = (th->header_len >> 4) << 2;

			if (pfx_set[pfx_index].current_bin_start_time.timestamp_s == 0 && pfx_set[pfx_index].current_bin_start_time.timestamp_ms == 0){
				pfx_set[pfx_index].current_bin_start_time.timestamp_s = ph.ts.timestamp_s;
				pfx_set[pfx_index].current_bin_start_time.timestamp_ms = ph.ts.timestamp_ms;
			}
			update_sw(&pfx_set[pfx_index], ph.ts, bin);
			int pos = search_hash_table(pfx_set[pfx_index].ht, ntohl(ih->src_ip), ntohl(ih->dst_ip), th->src_port, th->dst_port);
			if (pos == -1){
				//can't find the corresponding flow
				flow *tmp = (flow *)malloc(sizeof(flow));
				tmp->isnull = 0;
				tmp->src = ntohl(ih->src_ip);
				tmp->dst = ntohl(ih->dst_ip);
				tmp->src_p = th->src_port;
				tmp->dst_p = th->dst_port;
				tmp->expect_seq = ntohl(th->seq) + ntohs(ih->total_len) - ih_len - curr_buff_pos - tcp_hlen;
				tmp->curr_ack = ntohl(th->ack);
				tmp->last_size = ph.len;
				if (pfx_set[pfx_index].ht->count == pfx_set[pfx_index].ht->size){
					expand_count++;
					// hash_table_expand(pfx_set[pfx_index].ht);
				}
				else
					insert_hash_table(pfx_set[pfx_index].ht, tmp);
				free(tmp);
			}
			else{
				unsigned int current = ntohl(th->seq) + ntohs(ih->total_len) - ih_len - curr_buff_pos - tcp_hlen;
				// printf("Expect %u Current %u\n", pfx_set[pfx_index].ht->table[pos].expect_seq, current);
				if (current == pfx_set[pfx_index].ht->table[pos].expect_seq 
					&& current >= ntohl(th->seq) 
					&& ((ntohs(ih->total_len) - ih_len - curr_buff_pos - tcp_hlen) > 0)){
					// retransmission detection
					printf("%lu.%lu.%lu.%lu/%d\t%u.%06u\n", pfx_set[pfx_index].ip >> 24,
						(pfx_set[pfx_index].ip >> 16) & 0xff,
						(pfx_set[pfx_index].ip >> 8) & 0xff,
						pfx_set[pfx_index].ip & 0xff,
						pfx_set[pfx_index].slash,
						ph.ts.timestamp_s,
						ph.ts.timestamp_ms);
					int last_bin = (pfx_set[pfx_index].curr_sw_pos - 1) % BIN_NUM;
					pfx_set[pfx_index].sliding_window[last_bin] += 1;
					rt_count++;
				}
				pfx_set[pfx_index].ht->table[pos].expect_seq = current;
				pfx_set[pfx_index].ht->table[pos].curr_ack = ntohl(th->ack);
				pfx_set[pfx_index].ht->table[pos].last_size = ph.len;
			}
			free(th);
		}
		free(ih);
		// printf("%d\n", count);
	}

	//Memory free and summary
ERROR:
	if (buff){
		free(buff);
		buff=NULL;
	}
	if (fp){
		fclose(fp);
		fp =NULL;
	}
	if (pfx_set){
		int i;
		for (i=0;i<set_size;++i){
			free(pfx_set[i].sliding_window);
			free(pfx_set[i].ht);
		}
		free(pfx_set);
	}
	printf("Total expand count: %d\n", expand_count);

	printf("Total retransmission count: %d\n", rt_count);
	printf("Total tcp count: %d\n", tcp_count);
	printf("Total monitored packet count: %d\n", total_count);
	printf("Total packet count: %d\n", count);
	end = time(NULL);
	printf("The total time spent:%ld\n", end - start);

	return;
}

timestamp ts_minus(timestamp a, timestamp b){
	timestamp res;
	//assert a > b
	if (a.timestamp_ms < b.timestamp_ms){
		res.timestamp_ms = a.timestamp_ms + 1000000 - b.timestamp_ms;
		res.timestamp_s = a.timestamp_s - 1 - b.timestamp_s;
	}
	else{
		res.timestamp_s = a.timestamp_s - b.timestamp_s;
		res.timestamp_ms = a.timestamp_ms - b.timestamp_ms;
	}
	return res;
}

int ts_divide(timestamp a, timestamp b){
	return (int)((a.timestamp_s * 1000000 + a.timestamp_ms) / (b.timestamp_s * 1000000 + b.timestamp_ms));
}

int ts_cmp(timestamp a, timestamp b){
	if (a.timestamp_s < b.timestamp_s) 
		return -1;
	else if (a.timestamp_s == b.timestamp_s){
		if (a.timestamp_ms < b.timestamp_ms)
			return -1;
		else if (a.timestamp_ms == b.timestamp_ms)
			return 0;
		else
			return 1;
	}
	else
		return 1;
}

void update_sw(prefix *pfx, timestamp packet_time, timestamp bin){
	timestamp diff = ts_minus(packet_time, pfx->current_bin_start_time);

	int sw_sum = 0,p;
	for (p = 0;p < BIN_NUM;++p)
		sw_sum += pfx->sliding_window[p];
	if (ts_cmp(diff, bin) > 0){
		//have to move to the next bin
		// printf("%u.%u\n", pfx->current_bin_start_time.timestamp_s, pfx->current_bin_start_time.timestamp_ms);
		int shift = ts_divide(diff, bin);
		int i, j;
		for (i = pfx->curr_sw_pos, j = 0;j < shift;++j){
			sw_sum -= pfx->sliding_window[i];
			//show sw_sum
			// printf("SW_INFO|\t%lu.%lu.%lu.%lu/%d\t%u.%06u\t%d\n", 
			// 	pfx->ip >> 24,
			// 	(pfx->ip >> 16) & 0xff,
			// 	(pfx->ip >> 8) & 0xff,
			// 	pfx->ip & 0xff,
			// 	pfx->slash,
			// 	pfx->current_bin_start_time.timestamp_s + ((pfx->current_bin_start_time.timestamp_ms+i*bin.timestamp_ms)/1000000),
			// 	(pfx->current_bin_start_time.timestamp_ms + i*bin.timestamp_ms)%1000000,
			// 	sw_sum);
			i = (i + 1) % BIN_NUM;
			pfx->sliding_window[i] = 0;
		}
		pfx->curr_sw_pos = (pfx->curr_sw_pos + shift) % BIN_NUM;
		pfx->current_bin_start_time.timestamp_s += (pfx->current_bin_start_time.timestamp_ms + shift * bin.timestamp_ms) / 1000000;
		pfx->current_bin_start_time.timestamp_ms = (pfx->current_bin_start_time.timestamp_ms + shift * bin.timestamp_ms) % 1000000;
	}
	
	return;
}








