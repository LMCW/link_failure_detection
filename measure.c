#include "measure.h"

int pfx_file_size(char *filename){
	FILE *fp = fopen(filename, "r");
	char *buff = (void *)malloc(100);
	memset(buff, 0, 100);
	int i;
	for (i = 0;!feof(fp);++i){
		fgets(buff, 100, fp);
		if (strlen(buff) < 9){
			break;
		}
	}
	printf("Prefix file size: %d.\n", i);
	free(buff);
	fclose(fp);
	return i;
}

_prefix *_pfx_set_from_file(char *filename, int size){
	FILE *fp = fopen(filename, "r");

	char buff[256];
	memset(buff, 0, 256);

	int i;
	// for (i = 0;!feof(fp);++i){
	// 	fgets(buff, 100, fp);
	// 	if (strlen(buff) < 9){
	// 		break;
	// 	}
	// }
	// size = i;
	// printf("Prefix number: %d.\n", size);
	// rewind(fp);

	_prefix *set = (_prefix *)malloc(sizeof(_prefix) * size);
	// _prefix set[size];
	for (i = 0;i < size;++i){
		fgets(buff, 256, fp);
		if (strcmp(buff, "") != 0){
			int j = 0;
			for (;j < strlen(buff);++j)
				if (buff[j]=='/')
					break;
			buff[j] = 0;
			set[i].ip = ntohl(inet_addr(buff));
			set[i].slash = 0;
			for (j = j + 1;;++j){
				if (buff[j] > '9' || buff[j] < '0'){
					break;
				}
				set[i].slash = set[i].slash * 10 + (buff[j] - '0');
			}

			set[i].threshold = 0;
			set[i].ht = (void *)malloc(sizeof(_hash_table));
			// printf("%d\n", i);
			_hash_init(set[i].ht);
		}
	}

	printf("Load Complete.\n");
	fclose(fp);
	// free(buff);
	// printf("HAHA_2\n");
	qsort(set, size, sizeof(_prefix), _pfx_cmp);
	// for (i=0;i < size;++i){
	// 	printf("%lu.%lu.%lu.%lu/%d\n", set[i].ip >> 24,
	// 		(set[i].ip >> 16) & 0xff,
	// 		(set[i].ip >> 8) & 0xff,
	// 		set[i].ip & 0xff,
	// 		set[i].slash);
	// }
	return set;
}

int _pfx_cmp(const void *a, const void *b){
	if (((_prefix *)a)->ip < ((_prefix *)b)->ip)
		return -1;
	else if (((_prefix *)a)->ip == ((_prefix *)b)->ip)
		return 0;
	else
		return 1;
}

int _ip_pfx_match(unsigned long ip, _prefix pfx){
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

int _binary_search_ip(unsigned long ip, _prefix *pfx_set, int set_size){
	int hi,lo,mid,tmp;
	for (lo=0,hi = set_size - 1;lo <= hi;){
		mid = (lo+hi)/2;
		tmp = _ip_pfx_match(ip, pfx_set[mid]);
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

void rtt_measure(){
	trie_node *rib_root = load_rib();

	// char pfx_file[256];
	// memset(pfx_file, 0, 256);
	// printf("Prefix file name:");
	// scanf("%s", pfx_file);
	char *pfx_file = "/Users/chenzp/Documents/Research/link_failure_detection/trace_caida/2015/prefix_raw_2015_1.txt";
	int set_size = pfx_file_size(pfx_file);
	_prefix *pfx_set = _pfx_set_from_file(pfx_file, set_size);

	void *buff = NULL;
	buff = (void *)malloc(MAX_ETH_FRAME);
	if (buff == NULL){
		fprintf(stderr, "malloc buffer failed.\n");
		goto ERROR;
	}

	int readSize = 0, pkt_count;

	// char filename[256];
	// memset(filename, 0, 256);
	// printf("Pcap file name: ");
	// scanf("%s", filename);
	char *filename = "/Users/chenzp/Documents/Research/link_failure_detection/trace_caida/2015/equinix-chicago.dirA.20150219-125911.UTC.anon.pcap";

	FILE *fp = fopen(filename, "r");
	printf("Start Analyzing...\n");

	pcap_file_header pfh;
	pcap_header ph;

	//pcap file header
	fread(&pfh, sizeof(pcap_file_header), 1, fp);
	// prinfPcapFileHeader(&pfh);
	FILE *frtt = fopen("./rtt_sample.txt","w");

	for (pkt_count = 0;;++pkt_count){
		// printf("Sequence %d ", pkt_count);
		memset(buff, 0, MAX_ETH_FRAME);

		readSize = fread(&ph, sizeof(pcap_header),1,fp);
		if (readSize <= 0) 
			break;
		readSize = fread(buff, 1, ph.capture_len, fp);//what is the difference between the two order?
		if (readSize != ph.capture_len){
			fprintf(stderr, "pcap file parse error.\n");
			goto ERROR;
		}
		ip_header *ih = (ip_header *)malloc(20);

		int eth = 0;
		memcpy(ih, buff, 20);
		if (ih->ver_hlen != 0x45){
			eth += ETH_LENGTH;
			memcpy(ih, buff + ETH_LENGTH, 20);
		}
		// if (ntohl(ih->src_ip) != 893907583 || ntohl(ih->dst_ip) != 853564073){
		// 	free(ih);
		// 	continue;
		// }
		// printf("Before search packet prefix. ");
		unsigned long dst_ip = ntohl(ih->dst_ip);
		trie_node *tmp_node = trie_search(rib_root, ip_key_l(dst_ip));
		unsigned int tmp_pfx_ip = key_ip(tmp_node->pfx_key);
		int pfx_index = _binary_search_ip(tmp_pfx_ip, pfx_set, set_size);
		// printf("Search prefix Complete %d.\n", pfx_index);
		if (pfx_index <= 0){
			free(ih);
			continue;
		}
		if (ih==NULL) 
			printf("???\n");
		// printf("HAHA ");
		if (ih->protocol == 6){
			// printf("start analyze tcp packet. ");
			int ih_len = (ih->ver_hlen & 0xf) << 2;
			tcp_header *th = (tcp_header *)malloc(20);

			memcpy(th, buff + ih_len + eth, 20);

			if ((th->flags &0x10)==0||(th->flags&0x1)!=0){
				free(ih);
				free(th);
				continue;
			}
			// printf("Prepare tmp flow. ");
			int tcp_hlen = (th->header_len >> 4) << 2;
			_flow *tmp_f = (_flow *)malloc(sizeof(_flow));
			tmp_f->src_ip = ntohl(ih->src_ip);
			tmp_f->dst_ip = ntohl(ih->dst_ip);
			tmp_f->src_port = th->src_port;
			tmp_f->dst_port = th->dst_port;
			tmp_f->expect_seq = ntohl(th->seq) + ntohs(ih->total_len) - ih_len - eth - tcp_hlen;
			tmp_f->flight_size = 0;
			tmp_f->last_ts.timestamp_s = ph.ts.timestamp_s;
			tmp_f->last_ts.timestamp_ms = ph.ts.timestamp_ms;
			iat_queue_init(&(tmp_f->iq));
			Bucket *bkt = _search_hash_table(pfx_set[pfx_index].ht, tmp_f);
			// printf("Search flow Complete ");

			// printf("%u.%u\n", ph.ts.timestamp_s, ph.ts.timestamp_ms);
			if (bkt){
				// printf("Analyzing %d ", pkt_count);
				unsigned int current_expect_seq = ntohl(th->seq) + ntohs(ih->total_len) - ih_len - eth - tcp_hlen;
				if (current_expect_seq == bkt->f->expect_seq &&
					current_expect_seq >= ntohl(th->seq) &&
					(ntohs(ih->total_len) - ih_len - eth - tcp_hlen) > 0){
					//retransimission
					// printf("Retransimission! %d\n", pkt_count);
					//log rt

				}
				else{
					// printf("Normal packet %d Pfx_index %d ", pkt_count, pfx_index);
					// if (pfx_index == 12){
					// printf("Pfx_index 12");
					// if (pfx_index == 113){	
					unsigned int rtt = flight_update(bkt->f, tmp_f->last_ts);
					if (rtt){
						fprintf(frtt,"%d\t", pfx_index);
						fprintf(frtt,"Src %u.%u.%u.%u\t", bkt->f->src_ip >> 24,
							(bkt->f->src_ip >> 16) & 0xff,
							(bkt->f->src_ip >> 8) & 0xff,
							bkt->f->src_ip & 0xff);
						fprintf(frtt,"Dst %u.%u.%u.%u\t", bkt->f->dst_ip >> 24,
							(bkt->f->dst_ip >> 16) & 0xff,
							(bkt->f->dst_ip >> 8) & 0xff,
							bkt->f->dst_ip & 0xff);
						fprintf(frtt,"Src port: %u\t", bkt->f->src_port);
						fprintf(frtt,"Dst port: %u\t", bkt->f->dst_port);
						fprintf(frtt,"Rtt sample: %d\n", rtt);
					}
					// }

				}
				free(tmp_f);
				// printf("Free complete.\n");
			}
			else{
				// printf("Prepare to Insert %d ", pkt_count);
				_insert_hash_table(pfx_set[pfx_index].ht, tmp_f);
				// printf("Insert success.\n");
			}

			free(th);

		}
		free(ih);

	}
ERROR:
	//memory free
	printf("End Analyzing.\n");
	if (buff){
		free(buff);
	}
	if (fp){
		fclose(fp);
	}
	if (rib_root){
		// freeTrie(rib_root);
	}
	if (frtt){
		fclose(frtt);
	}

	return;
}



