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

int loadPcap(){
	printf("sizeof:int %lu,unsigned int %lu,char %lu,unsigned char %lu,short:%lu,unsigned short:%lu,long:%lu\n",
		    sizeof(int),sizeof(unsigned int),sizeof(char),sizeof(unsigned char),sizeof(short),sizeof(unsigned short), sizeof(long));
	pcap_file_header pfh;
	pcap_header ph;
	FlowQueue fq;
	queue_init(&fq,MAX_QUEUE_LENGTH);
	int count = 0;
	void *buff = NULL;
	int readSize = 0;
	int ret = 0;

	char *filename;
	filename = (void *)malloc(100);
	memset(filename,0,100);
	printf("Pcap filename:");
	scanf("%s", filename);
	FILE *fp = fopen(filename, "rw");
	if (fp ==NULL){
		fprintf(stderr, "Open file %s error.\n", filename);
		ret = ERROR_FILE_OPEN_FAILED;
		goto ERROR;
	}

	time_t start, end;
	start = time(NULL);

	fread(&pfh, sizeof(pcap_file_header), 1, fp);
	prinfPcapFileHeader(&pfh);

	buff = (void *)malloc(MAX_ETH_FRAME);

	int tcp_count = 0;
	int ret_count = 0;
	int prt = -1;
	for (count=1;;++count){
		// break;
		memset(buff,0,MAX_ETH_FRAME);
		//read pcap header to get a packet
		readSize = fread(&ph, sizeof(pcap_header),1,fp);
		if (readSize <= 0) break;
		// printfPcapHeader(&ph);

		/*print the first timestamp*/
		if (count == 1 || count == 16829835){
			printfPcapHeader(&ph);
		}

		if (buff == NULL){
			fprintf(stderr, "malloc memory faild.\n");
			ret = ERROR_MEM_ALLOC_FAILED;
			goto ERROR;
		}

		//get a packet data frame
		readSize = fread(buff, 1, ph.capture_len, fp);
		if (readSize != ph.capture_len){
			free(buff);
			fprintf(stderr, "pcap file parse error.\n");
			ret = ERROR_PCAP_PARSE_FAILED;
			goto ERROR;
		}
		prt = parse_normal(buff, ph.capture_len, &fq, ph.len);
		// printf("The size of queue: %d\n", fq.count);
		if (prt == 6 || prt == 7777) ++tcp_count;
		if (prt == 7777){
			// printf("%u.%u\n", ph.ts.timestamp_s, ph.ts.timestamp_ms);
			printf("Retransmission: %d\n", count);
			++ret_count; 
		}
		// printf("===count:%d,readSize:%d===\n",count,readSize);
		if (feof(fp) || readSize <= 0) 
			break;
	}

ERROR:
	if (buff){
		free(buff);
		buff=NULL;
	}
	if (fp){
		fclose(fp);
		fp =NULL;
	}
	queue_free(&fq);
	printf("The total packet count:%d, the total tcp packet count:%d, monitored retransmission:%d\n", count, tcp_count, ret_count);

	end = time(NULL);
	printf("The total time spent:%ld\n", end - start);
	return ret;
}

int queue_match(ip_header ih, tcp_header th, FlowQueue *fq){
	int i,flag,pos;
	i = (fq->head - 1) % fq->size;
	if (i <0)
		i = i + fq->size;
	if (i >= fq->count)
		return -1;
	// printf("The head of queue: %d, tail: %d\n", i, fq->tail);
	pos = -1;
	flag = 0;
	while(i != fq->tail){
		flag = flow_match(ih.src_ip, ih.dst_ip, th.src_port, th.dst_port, fq->queue[i]);
		if (flag) {
			pos = i;
			break;
		}
		i = (i-1) % fq->size;
		if (i < 0)
			i = i + fq->size;
	}

	if (pos == -1){
		flag = flow_match(ih.src_ip, ih.dst_ip, th.src_port, th.dst_port, fq->queue[fq->tail]);
		if (flag)
			pos = fq->tail;
	}
	// printf("\n");
	return pos;
}

int parse(void *data, int size, FlowQueue *fq, int len){

	ip_header *ih;
	int ret;
	ih = (void *)malloc(20);
	memcpy(ih, data, 20);
	int ih_len = (ih->ver_hlen % 16) * 4;
	ret = ih->protocol;
	if (ret == 6){
		//tcp packet
		tcp_header *th;
		th = (void *)malloc(20);
		memcpy(th, data + ih_len, 20);
		// printf("Seq:%u Ack:%u\n",ntohl(th->seq), ntohl(th->ack));
		// printf("src port: %u\n", ntohs(th->src_port));
		int tcp_hlen = (th->header_len >> 4) * 4;
		int pos;
		pos = queue_match(*ih, *th, fq);
		// printf("Pos: %d\n", pos);
		if (pos == -1){//can't find the corresponding flow
			flow *tmp;
			tmp = (void *)malloc(sizeof(flow));
			tmp->src = ih->src_ip;
			tmp->dst = ih->dst_ip;
			tmp->src_p = th->src_port;
			tmp->dst_p = th->dst_port;
			tmp->expect_seq = ntohl(th->seq) + (ntohs(ih->total_len) - ih_len - tcp_hlen);
			tmp->curr_ack = ntohl(th->ack);
			tmp->last_size = len;
			// printf("Expect_seq: %u\n", tmp->expect_seq);
			if (fq->size == fq->count){
				// printf("%d %d\n", fq->size, fq->count);
				queue_dequeue(fq);
			}
			queue_enqueue(fq, tmp);
			free(tmp);
		}
		else{//found
			int current;
			current = ntohl(th->seq) + (ntohs(ih->total_len) - ih_len - tcp_hlen);
			if (current == fq->queue[pos].expect_seq && ((ntohs(ih->total_len) - ih_len - tcp_hlen) > 0 || (th->flags & 2))){
				// printf("Expect_seq: %u\n", current);
				if (current >= ntohl(th->seq)){
					ret = 7777;
				}


				if (th->flags & 1){//FIN packet
					ret = 6;
				}
			}
			fq->queue[pos].expect_seq = current;
			fq->queue[pos].curr_ack = ntohl(th->ack);
			fq->queue[pos].last_size = len;
		}
		free(th); 
	}

	free(ih);
	return ret;
}

int parse_normal(void *data, int size, FlowQueue *fq, int len){
	//judge if there is an ethernet header
	ip_header *ih;
	int ret;
	ih = (void *)malloc(20);
	memcpy(ih, data, 20);
	if (ih->ver_hlen == 0x45){//raw packer data without eth header
		free(ih);
		return parse(data, size, fq, len);
	}
	else{//Eth header exists
		memcpy(ih, data + ETH_LENGTH, 20);
		ret = ih->protocol;
		int ih_len = (ih->ver_hlen % 16) * 4;
		if (ret == 6){
			tcp_header *th;
			th = (void *)malloc(20);
			memcpy(th, data + ih_len + ETH_LENGTH, 20);

			//tcp header length
			int tcp_hlen = (th->header_len >> 4) * 4;
			int pos;
			pos = queue_match(*ih, *th, fq);
			// printf("Pos: %d\n", pos);
			// printf("%u %u\n", ntohl(th->seq), ntohl(th->seq) + size - ih_len - ETH_LENGTH - tcp_hlen);
			if (pos == -1){//can't find the corresponding flow
				flow *tmp;
				tmp = (void *)malloc(sizeof(flow));
				tmp->src = ih->src_ip;
				tmp->dst = ih->dst_ip;
				tmp->src_p = th->src_port;
				tmp->dst_p = th->dst_port;
				tmp->expect_seq = ntohl(th->seq) + ntohs(ih->total_len) - ih_len - ETH_LENGTH - tcp_hlen;
				tmp->curr_ack = ntohl(th->ack);
				tmp->last_size = len;
				// printf("%u %u %u %u\n", tmp->expect_seq, ntohs(ih->total_len), size, th->header_len);
				if (fq->size == fq->count){
					// printf("%d %d\n", fq->size, fq->count);
					queue_dequeue(fq);
				}
				queue_enqueue(fq, tmp);
				free(tmp);
			}
			else{//found
				int current;
				current = ntohl(th->seq) + (ntohs(ih->total_len) - ih_len - ETH_LENGTH - tcp_hlen);
				// printf("%d\n", (size - ih_len - ETH_LENGTH - tcp_hlen));
				// printf("%u %u\n", ntohl(th->seq), ntohs(ih->total_len));
				if (current == fq->queue[pos].expect_seq && ntohl(th->ack) == fq->queue[pos].curr_ack && fq->queue[pos].last_size <= len){
				// if (current == fq->queue[pos].expect_seq && ntohl(th->ack) == fq->queue[pos].curr_ack){
					// struct in_addr src, dst;
					// src.s_addr = ih->src_ip;
					// dst.s_addr = ih->dst_ip;
					// printf("TCP retransmission: src:%u dst:%u, expected seq is: %u, current seq is: %u\n", ih->src_ip, ih->dst_ip, fq->queue[pos].expect_seq, current);
					// printf("TCP retransmission: src:%s dst:%s\n", inet_ntoa(src), inet_ntoa(dst));
					ret = 7777;
				}
				fq->queue[pos].expect_seq = current;
				fq->queue[pos].curr_ack = ntohl(th->ack);
				fq->queue[pos].last_size = len;
			}
			free(th); 
		}

		free(ih);
		return ret;
	}
}

unsigned long get_dst_ip(void *data){
	ip_header *ih = NULL;
	ih = (ip_header *)malloc(20);
	memcpy(ih, data, 20);
	if (ih->ver_hlen != 0x45)
		memcpy(ih, data + ETH_LENGTH, 20);
	return (unsigned long)ih->dst_ip;
}

int queue_init(FlowQueue *Q, int size){
	Q->head = 0;
	Q->tail = 0;
	Q->count = 0;
	Q->queue = (flow *)malloc(size * sizeof(flow));
	if (Q->queue){
		Q->size = size;
		return 1;
	}
	else{
		Q->size = 0;
		fprintf(stderr, "Queue init failed\n");
		return 0;
	}
}

int queue_free(FlowQueue *Q){
	free(Q->queue);
	Q->head = 0;
	Q->tail = 0;
	Q->count = 0;
	Q->size = 0;
	Q->queue = NULL;
	return 1;
}

int queue_empty(FlowQueue * Q) {
    if (Q->count == 0)
        return 1;
    else 
    	return 0;
}

int queue_enqueue(FlowQueue *Q, flow *item){
	if (Q->count > Q->size)
		return -1;

	memcpy(&(Q->queue[Q->head]), item, sizeof(flow));
	// printf("Enqueue flow src: %u, dst:%u\n", Q->queue[Q->head].src, Q->queue[Q->head].dst);
	// if (Q->size == Q->count + 1)
	// 	printf("Enqueue: %u %u %u\n", Q->head,Q->queue[Q->head].src, Q->queue[Q->head].dst);
	Q->head = (Q->head + 1) % Q->size;
	Q->count++;
	return 1;
}

int queue_dequeue(FlowQueue *Q){
	if (!queue_empty(Q)){
		// *item = Q->queue[Q->tail];
		// printf("Dequeue: %u %u %u\n", Q->tail, Q->queue[Q->tail].src, Q->queue[Q->tail].dst);
		Q->tail = (Q->tail + 1) % Q->size;
		Q->count--;
		return 1;
	}
	return 0;
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
		set[i].fq = (FlowQueue *)malloc(sizeof(FlowQueue));
		queue_init(set[i].fq, MAX_QUEUE_LENGTH);
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
	int set_size = 12231;
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
			continue;//not belong to the prefixes to monitor
		}
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

			int pos = queue_match(*ih, *th, pfx_set[pfx_index].fq);
			if (pfx_set[pfx_index].current_bin_start_time.timestamp_s == 0 && pfx_set[pfx_index].current_bin_start_time.timestamp_ms == 0){
				pfx_set[pfx_index].current_bin_start_time.timestamp_s = ph.ts.timestamp_s;
				pfx_set[pfx_index].current_bin_start_time.timestamp_ms = ph.ts.timestamp_ms;
			}
			update_sw(&pfx_set[pfx_index], ph.ts, bin);
			if (pos == -1){
				//can't find the corresponding flow
				flow *tmp = (flow *)malloc(sizeof(flow));
				tmp->src = ntohl(ih->src_ip);
				tmp->dst = ntohl(ih->dst_ip);
				tmp->src_p = th->src_port;
				tmp->dst_p = th->dst_port;
				tmp->expect_seq = ntohl(th->seq) + ntohs(ih->total_len) - ih_len - curr_buff_pos - tcp_hlen;
				tmp->curr_ack = ntohl(th->ack);
				tmp->last_size = ph.len;
				if (pfx_set[pfx_index].fq->count == pfx_set[pfx_index].fq->size)
					queue_dequeue(pfx_set[pfx_index].fq);
				queue_enqueue(pfx_set[pfx_index].fq, tmp);
				free(tmp);
			}
			else{
				unsigned int current = ntohl(th->seq) + ntohs(ih->total_len) - ih_len - curr_buff_pos - tcp_hlen;
				// printf("Expect %u Current %u\n", pfx_set[pfx_index].fq->queue[pos].expect_seq, current);
				if (current == pfx_set[pfx_index].fq->queue[pos].expect_seq 
					&& current >= ntohl(th->seq) 
					&& ((ntohs(ih->total_len) - ih_len - curr_buff_pos - tcp_hlen) > 0)){
					// retransmission detection
					int last_bin = (pfx_set[pfx_index].curr_sw_pos - 1) % BIN_NUM;
					pfx_set[pfx_index].sliding_window[last_bin] += 1;
					rt_count++;
				}
				pfx_set[pfx_index].fq->queue[pos].expect_seq = current;
				pfx_set[pfx_index].fq->queue[pos].curr_ack = ntohl(th->ack);
				pfx_set[pfx_index].fq->queue[pos].last_size = ph.len;
			}
			free(th);
		}
		free(ih);
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
			queue_free(pfx_set[i].fq);
		}
		free(pfx_set);
	}

	printf("Total retransmission count: %d\n", rt_count);
	printf("Total tcp count: %d\n", tcp_count);
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
			printf("SW_INFO|\t%lu.%lu.%lu.%lu/%d\t%u.%06u\t%d\n", 
				pfx->ip >> 24,
				(pfx->ip >> 16) & 0xff,
				(pfx->ip >> 8) & 0xff,
				pfx->ip & 0xff,
				pfx->slash,
				pfx->current_bin_start_time.timestamp_s + ((pfx->current_bin_start_time.timestamp_ms+i*bin.timestamp_ms)/1000000),
				(pfx->current_bin_start_time.timestamp_ms + i*bin.timestamp_ms)%1000000,
				sw_sum);
			i = (i + 1) % BIN_NUM;
			pfx->sliding_window[i] = 0;
		}
		pfx->curr_sw_pos = (pfx->curr_sw_pos + shift) % BIN_NUM;
		pfx->current_bin_start_time.timestamp_s += (pfx->current_bin_start_time.timestamp_ms + shift * bin.timestamp_ms) / 1000000;
		pfx->current_bin_start_time.timestamp_ms = (pfx->current_bin_start_time.timestamp_ms + shift * bin.timestamp_ms) % 1000000;
	}
	
	return;
}








