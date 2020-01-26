#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>
#include "pcap.h"

#define MAX_ETH_FRAME 1514
#define ETH_LENGTH 14
#define ERROR_FILE_OPEN_FAILED -1
#define ERROR_MEM_ALLOC_FAILED -2
#define ERROR_PCAP_PARSE_FAILED -3

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





