#include "pcap.h"

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
	char *filename = (void *)malloc(256);
	printf("Prefix filename: ");
	scanf("%s",filename);
	FILE *fp = fopen(filename, "r");
	char *buff = (void *)malloc(100);
	memset(buff,0,100);
	char tmp[20];
	memset(tmp,0,20);

	int i;
	for (i=0;i < size && !feof(fp);++i){
		//initialization of each prefix
		fgets(buff, 100, fp);
		// printf("%s", buff);
		int j = 0, len;
		len = strlen(buff);
		// printf("HAHA %d\n", len);
		for (;j < len;++j)
			if (buff[j]=='/') break;

		buff[j] = 0;
		strcpy(tmp, buff);
		// printf("%s ", tmp);
		set[i].ip = ntohl(inet_addr(tmp));
		set[i].slash = 0;
		for (j=j+1;; ++j){
			if (buff[j] > '9' || buff[j] < '0')
				break;
			set[i].slash = set[i].slash * 10 + (buff[j]-'0');
		}
		// printf("%d\n", set[i].slash);
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
	trie_node *rib_root = load_rib();
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
	int set_size = 1829;
	// printf("How many prefixes to monitor?");
	// scanf("%d", &set_size);
	if (set_size <= 0)
		return;
	prefix *pfx_set = pfx_set_from_file(set_size); //TODO: determine the count of prefixes to monitor
	timestamp *timer_set = (timestamp *)malloc(sizeof(timestamp) * set_size);
	memset(timer_set, 0, sizeof(timestamp) * set_size);

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
	int not_match = 0;

	start = time(NULL);
	//monitoring pcap file
	FILE *log_fp = fopen("log.txt","w");
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
		unsigned long dst_ip = ntohl(ih->dst_ip);
		trie_node *tmp_node = trie_search(rib_root, ip_key_l(dst_ip));
		unsigned int tmp_pfx_ip = key_ip(tmp_node->pfx_key);
		int pfx_index = binary_search_ip(tmp_pfx_ip, pfx_set, set_size);//TODO: ip to pfx mapping new method
		if (pfx_index == -1) {
			// pfx_index = 0;
			// printf("%lu.%lu.%lu.%lu\t%lu.%lu.%lu.%lu\n", 
			// 	dst_ip >> 24,
			// 	(dst_ip >> 16) & 0xff,
			// 	(dst_ip >> 8) & 0xff,
			// 	dst_ip & 0xff,
			// 	tmp_pfx_ip >> 24,
			// 	(tmp_pfx_ip >> 16) & 0xff,
			// 	(tmp_pfx_ip >> 8) & 0xff,
			// 	tmp_pfx_ip & 0xff);
			not_match++;
			free(ih);
			continue;
		}
		else if (pfx_index == 0){
			free(ih);
			continue;
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
			update_sw(&pfx_set[pfx_index], ph.ts, bin, log_fp);
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
				tmp->last_ts.timestamp_s = ph.ts.timestamp_s;
				tmp->last_ts.timestamp_ms = ph.ts.timestamp_ms;
				tmp->rd.smooth_rtt = 0;
				tmp->rd.rtt_var = 0;
				tmp->rd.rto = 3;
				if (pfx_set[pfx_index].ht->count == pfx_set[pfx_index].ht->size){
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
					// printf("%lu.%lu.%lu.%lu/%d\t%u.%06u\n", pfx_set[pfx_index].ip >> 24,
					// 	(pfx_set[pfx_index].ip >> 16) & 0xff,
					// 	(pfx_set[pfx_index].ip >> 8) & 0xff,
					// 	pfx_set[pfx_index].ip & 0xff,
					// 	pfx_set[pfx_index].slash,
					// 	ph.ts.timestamp_s,
					// 	ph.ts.timestamp_ms);
					int last_bin = (pfx_set[pfx_index].curr_sw_pos - 1) % BIN_NUM;
					pfx_set[pfx_index].sliding_window[last_bin] += 1;
					rt_count++;
				}
				else{
					//if a packet is not a retransmission, we can use it to measure rtt
					timestamp rtt_sample = ts_minus(ph.ts, pfx_set[pfx_index].ht->table[pos].last_ts);
					//if the sample is greater than some threshold, abandon this sample
					int ms_sample = rtt_sample.timestamp_s * 1000000 + rtt_sample.timestamp_ms;
					if (ms_sample <= 2000000){
						//flow smooth rtt update
						rtt_update(&(pfx_set[pfx_index].ht->table[pos].rd), ms_sample);
						// if (pfx_index == 16)
							// printf("%d\n", ms_sample);
						// threshold_set(&(pfx_set[pfx_index]), &(timer_set[pfx_index]));
					}
				}
				pfx_set[pfx_index].ht->table[pos].expect_seq = current;
				pfx_set[pfx_index].ht->table[pos].curr_ack = ntohl(th->ack);
			}
			free(th);
		}
		free(ih);
		// printf("%d\n", count);
	}

	//Memory free and summary
ERROR:
	end = time(NULL);

	// char *line = (char *)malloc(256);
	// printf("End Analyze.\n");
	// while (1){	
	// 	memset(line, 0, 256);
	// 	scanf("%s", line);
	// 	if (strcmp(line, "exit") == 0){
	// 		free(line);
	// 		break;
	// 	}
	// }
	if (buff){
		free(buff);
		buff=NULL;
	}
	if (fp){
		fclose(fp);
		fp =NULL;
	}
	if (log_fp){
		fclose(log_fp);
		log_fp = NULL;
	}
	if (pfx_set){
		//flow count statistics
		FILE *flow_count = fopen("flow_stats.txt","w");
		int i;
		for (i = 0;i < set_size;++i){
			fprintf(flow_count, "Prefix flow count|\t%lu.%lu.%lu.%lu/%d\t%d\n", 
				pfx_set[i].ip >> 24,
				(pfx_set[i].ip >> 16) & 0xff,
				(pfx_set[i].ip >> 8) & 0xff,
				pfx_set[i].ip & 0xff,
				pfx_set[i].slash, 
				pfx_set[i].ht->count);
		}
		for (i = 0;i < set_size;++i){
			free(pfx_set[i].sliding_window);
			free(pfx_set[i].ht);
		}
		fclose(flow_count);
		free(pfx_set);	
	}
	if (rib_root){
		freeTrie(rib_root);
	}
	printf("Not match amount: %d\n", not_match);
	printf("Total retransmission count: %d\n", rt_count);
	printf("Total tcp count: %d\n", tcp_count);
	printf("Total monitored packet count: %d\n", total_count);
	printf("Total packet count: %d\n", count);
	
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

void update_sw(prefix *pfx, timestamp packet_time, timestamp bin, FILE *fp){
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
			fprintf(fp, "SW_INFO|\t%lu.%lu.%lu.%lu/%d\t%u.%06u\t%d\t%d\n", 
				pfx->ip >> 24,
				(pfx->ip >> 16) & 0xff,
				(pfx->ip >> 8) & 0xff,
				pfx->ip & 0xff,
				pfx->slash,
				pfx->current_bin_start_time.timestamp_s + ((pfx->current_bin_start_time.timestamp_ms+i*bin.timestamp_ms)/1000000),
				(pfx->current_bin_start_time.timestamp_ms + i*bin.timestamp_ms)%1000000,
				sw_sum,
				pfx->ht->count);
			i = (i + 1) % BIN_NUM;
			pfx->sliding_window[i] = 0;
		}
		pfx->curr_sw_pos = (pfx->curr_sw_pos + shift) % BIN_NUM;
		pfx->current_bin_start_time.timestamp_s += (pfx->current_bin_start_time.timestamp_ms + shift * bin.timestamp_ms) / 1000000;
		pfx->current_bin_start_time.timestamp_ms = (pfx->current_bin_start_time.timestamp_ms + shift * bin.timestamp_ms) % 1000000;
	}
	
	return;
}

void threshold_set(prefix *pfx, timestamp *timer){
	if (timer->timestamp_s < 10){
		//if timer hasn't reach 10 seconds, do not change the threshold
		return;
	}
	int i;
	for (i=0;i < pfx->ht->size;++i){
		if (pfx->ht->table[i].isnull) 
			continue;

	}

	timer->timestamp_s = 0;
	timer->timestamp_ms = 0;
	return;
}








