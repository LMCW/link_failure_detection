#include "prefix.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MAX_ETH_FRAME 1514
#define ETH_LENGTH 14
#define ERROR_FILE_OPEN_FAILED -1
#define ERROR_MEM_ALLOC_FAILED -2
#define ERROR_PCAP_PARSE_FAILED -3

int init(prefix_set *S, int Num){
	S->count = 0;
	S->statistic = (int *)malloc(Num * sizeof(int));
	S->ip_set = (int *)malloc(Num * sizeof(int));
	S->slash_set = (int *)malloc(Num * sizeof(int));
	if (S->statistic && S->ip_set && S->slash_set){
		S->size = Num;
		return 1;
	}
	else{
		fprintf(stderr, "Queue init failed\n");
		return 0;
	}
}

int findPrefix(prefix_set *S, int ip, int slash){
	int i;
	for (i = 0;i < S->count;++i){
		if (S->ip_set[i] == ip && S->slash_set[i] == slash){
			return i;
		}
	}
	return -1;
}

int newPrefix(prefix_set *S, int ip, int slash){
	if (S->count == S->size){
		printf("Set if full!\n");
		return -1;
	}
	S->ip_set[S->count] = ip;
	S->slash_set[S->count] = slash;
	S->statistic[S->count] = 1;
	S->count += 1;
	return S->count - 1;
}

int showSet(prefix_set *S){
	int i, ip, slash;
	for (i=0;i < S->count;++i){
		ip = S->ip_set[i];
		slash = S->slash_set[i];
		printf("%d %d.%d.%d.%d/%d: %d\n", i, (ip & 0xff000000) >> 24, (ip & 0x00ff0000) >> 16, (ip & 0x0000ff00) >> 8, ip & 0x000000ff, 32 - slash, S->statistic[i]);
	}
	return 0;
}

int set2file(prefix_set *S, int threshold){
	FILE *fp = fopen("prefix.txt","w");
	int i, ip, slash, count;
	count = 0;
	for (i=0;i < S->count;++i){
		if (S->statistic[i] < threshold)
			continue;
		ip = S->ip_set[i];
		slash = S->slash_set[i];
		fprintf(fp, "%d.%d.%d.%d/%d\n", (ip & 0xff000000) >> 24, (ip & 0x00ff0000) >> 16, (ip & 0x0000ff00) >> 8, ip & 0x000000ff, 32 - slash);
		count += 1;
	}
	printf("Wrote: %d\n", count);
	return 0;
}

int setfree(prefix_set *S){
	free(S->statistic);
	free(S->ip_set);
	free(S->slash_set);
	S->count = 0;
	S->size = 0;
	return 1;
}

int generateSet(prefix_set *S, int slash){
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
	FILE *fp = fopen(filename, "r");
	if (fp ==NULL){
		fprintf(stderr, "Open file %s error.\n", filename);
		ret = ERROR_FILE_OPEN_FAILED;
		goto ERROR;
	}

	time_t start, end;
	start = time(NULL);

	fread(&pfh, sizeof(pcap_file_header), 1, fp);
	// prinfPcapFileHeader(&pfh);

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
		// if (count == 1 || count == 16829835){
		// 	printfPcapHeader(&ph);
		// }

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

		ip_header *ih;
		ih = (void *)malloc(20);
		memcpy(ih, buff, 20);
		if (ih->ver_hlen != 0x45){//packet with ethernet header
			memcpy(ih, buff + ETH_LENGTH, 20);
		}
		int ip,pos;
		ip = ih->src_ip >> slash << slash;
		pos = findPrefix(S, ip, slash);
		if (pos != -1){//found
			S->statistic[pos] += 1;
		}
		else{//new prefix
			newPrefix(S, ip, slash);
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

	// showSet(S);
	set2file(S, 50);
	setfree(S);

	end = time(NULL);
	printf("The total time spent:%ld\n", end - start);
	return ret;
}