#include "prefix.h"
#include "hash_table.h"
#include "trie.h"

int pfx_file_size(char const *filename){
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

prefix *pfx_set_from_file(char const *filename, int set_size){
	FILE *fp = fopen(filename, "r");
	char *buff = (void *)malloc(256);
	memset(buff, 0, 256);
	prefix *set = (prefix *)malloc(sizeof(prefix) * set_size);
	int i;
	for (i = 0;i < set_size;++i){
		fgets(buff, 256, fp);
		if (strcmp(buff,"")!=0){
			int j = 0;
			for (;j < strlen(buff);++j)
				if (buff[j] == '/')
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

			set[i].thresh_p = 0.5;
			set[i].ht = (void *)malloc(sizeof(hash_table));
			set[i].sliding_window = (int *)malloc(sizeof(int) * BIN_NUM);
			memset(set[i].sliding_window, 0, sizeof(int) * BIN_NUM);
			set[i].curr_sw_pos = 0;
			set[i].current_bin_start_time.timestamp_s = 0;
			set[i].current_bin_start_time.timestamp_ms = 0;
			// printf("%d\n", i);
			hash_init(set[i].ht);
		}
	}
	printf("Load Complete.\n");
	qsort(set, set_size, sizeof(prefix), pfx_cmp);
	fclose(fp);
	free(buff);
	return set;
}

int ip_pfx_match(unsigned long ip, prefix pfx){
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
	for (lo=0,hi = set_size - 1;lo <= hi;){
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

int pfx_cmp(const void *a, const void *b){
	if (((prefix *)a)->ip < ((prefix *)b)->ip)
		return -1;
	else if (((prefix *)a)->ip == ((prefix *)b)->ip)
		return 0;
	else
		return 1;
}

float update_sw(prefix *pfx, timestamp packet_time, timestamp bin, FILE *fp){
	float ret = 0;
	timestamp active_threshold;
	active_threshold.timestamp_s = 0;
	active_threshold.timestamp_ms = 500000;
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
			if (sw_sum > BASIC_THRESHOLD){
				//calculate active flow count
				int afc = 0, s;
				for (s = 0;s < HASH_TABLE_INIT_SIZE;++s){
					Bucket *tmp = pfx->ht->buckets[s];
					while (tmp){
						timestamp tmp_ts;
						tmp_ts.timestamp_s = pfx->current_bin_start_time.timestamp_s + ((pfx->current_bin_start_time.timestamp_ms+j*bin.timestamp_ms)/1000000);
						tmp_ts.timestamp_ms = (pfx->current_bin_start_time.timestamp_ms + j*bin.timestamp_ms)%1000000;
						timestamp time_diff = ts_minus(tmp_ts, tmp->f->last_ts);
						if (ts_cmp(tmp_ts, tmp->f->last_ts) < 0){
							// printf("%u.%u  %u.%u\n", tmp_ts.timestamp_s, tmp_ts.timestamp_ms, tmp->f->last_ts.timestamp_s, tmp->f->last_ts.timestamp_ms);
							afc += 1;
						}
						else if (ts_cmp(time_diff, active_threshold) < 0){
							afc += 1;
						}
						// if (tmp->f->is_active){
						// 	afc += 1;
						// }
						tmp = tmp->next;
					}
				}
				fprintf(fp, "SW_INFO|\t%lu.%lu.%lu.%lu/%d\t%u.%06u\t%d\t%d\n", 
					pfx->ip >> 24,
					(pfx->ip >> 16) & 0xff,
					(pfx->ip >> 8) & 0xff,
					pfx->ip & 0xff,
					pfx->slash,
					pfx->current_bin_start_time.timestamp_s + ((pfx->current_bin_start_time.timestamp_ms+j*bin.timestamp_ms)/1000000),
					(pfx->current_bin_start_time.timestamp_ms + j*bin.timestamp_ms)%1000000,
					sw_sum,
					// pfx->ht->elem_num);
					afc);
				if (sw_sum >= pfx->thresh_p * afc){
					float tmp_frac = (float)sw_sum / afc;
					if (tmp_frac > ret)
						ret = tmp_frac;
				}
			}
			i = (i + 1) % BIN_NUM;
			pfx->sliding_window[i] = 0;
		}
		pfx->curr_sw_pos = (pfx->curr_sw_pos + shift) % BIN_NUM;
		pfx->current_bin_start_time.timestamp_s += (pfx->current_bin_start_time.timestamp_ms + shift * bin.timestamp_ms) / 1000000;
		pfx->current_bin_start_time.timestamp_ms = (pfx->current_bin_start_time.timestamp_ms + shift * bin.timestamp_ms) % 1000000;
	}
	
	return ret;
}