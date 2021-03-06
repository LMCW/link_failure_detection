#include "prefix.h"
#include "pcap.h"
#include "trie.h"
#include "timestamp.h"
#include "flow.h"
#include "hash_table.h"
#include "string.h"
#include "stdlib.h"
#include "probability.h"
#include "simple_prefix.h"
#include "analyze.h"

#define myFormatStringByMacro_ReturnFormatString(format, ...) \
({ \
    int size = snprintf(NULL, 0, format, ##__VA_ARGS__);\
    size++; \
    char *buf = (char *)malloc(size); \
    snprintf(buf, size, format, ##__VA_ARGS__); \
    buf; \
});

#define RTT_MEASURE_TIME 0

void int2filename(int i, char *filename){
	strcpy(filename, "./rtt/");
	int digit_num, tmp = i, j;
	for (digit_num = 1;tmp >= 10;++digit_num){
		tmp = tmp / 10;
	}
	// printf("Digit num: %d\n", digit_num);
	for (j = 0, tmp = i;j < digit_num;++j){
		// printf("%d\n", 6 + digit_num - 1 - j);
		filename[6 + digit_num - 1 - j] = (tmp % 10) + '0';
		tmp = tmp / 10;
	}
	char const *aaa = ".txt";
	strcpy(filename + 6 + digit_num, aaa);
	return;
}

char *pfx2filename(prefix *pfx){
	char *ret = myFormatStringByMacro_ReturnFormatString("./rtt/%lu.%lu.%lu.%lu_%d_rtt.txt",
		pfx->ip >> 24,
		(pfx->ip >> 16) & 0xff,
		(pfx->ip >> 8) & 0xff,
		pfx->ip & 0xff,
		pfx->slash);
	return ret;
}

int main(int argc, char const *argv[])
{
	if (argc != 5){
		printf("Usage: pcaptest [as_rel] [rib] [prefix] [pcap]\n");
		return 1;
	}
	link_statistic(argv[3], argv[1], argv[2], argv[4]);
	return 0;

	//generate prefix file from pcap file
	pcap_to_raw_set(argv[4], argv[1], argv[2], argv[3]);
	//load rib
	trie_node *rib_root = load_rib(argv[1], argv[2]);

	//load prefix file
	int set_size = pfx_file_size(argv[3]);
	prefix *pfx_set = pfx_set_from_file(argv[3], set_size);

	//load pcap file
	FILE *fp = fopen(argv[4],"r");

	//open rtt file
	FILE *frtt = fopen("./rtt_sample.txt","w");

	char log_file_name[100];
	memset(log_file_name, 0, 100);
	char const* log_f = "./log/2013/log_";//15
	strcpy(log_file_name, log_f);
	memcpy(log_file_name + 15, argv[4] + 44, 11);
	FILE *log_fp = fopen(log_file_name,"w");

	char suspect_file_name[100];
	memset(suspect_file_name, 0, 100);
	char const *suspect_f = "./suspect/2013/suspect_";//23
	strcpy(suspect_file_name, suspect_f);
	memcpy(suspect_file_name + 23, argv[4] + 44, 11);
	FILE *suspect = fopen(suspect_file_name,"w");

	char rt_file_name[100];
	memset(rt_file_name, 0, 100);
	char const *rt_f = "./retransmission/2013/rt_";//25
	strcpy(rt_file_name, rt_f);
	memcpy(rt_file_name + 25, argv[4] + 44, 11);
	FILE *frt = fopen(rt_file_name,"w");

	//pcap analyze
	int count, eth, flag = 0;
	int readSize = 0;

	void *buff = (void *)malloc(MAX_ETH_FRAME);
	ip_header *ih = (ip_header *)malloc(20);
	tcp_header *th = (tcp_header *)malloc(20);
	
	timestamp start_ts;

	timestamp bin;
	bin.timestamp_s = 0;
	bin.timestamp_ms = 80000;

	timestamp window;
	window.timestamp_s = 0;
	window.timestamp_ms = 800000;

	// timestamp active_threshold;
	// active_threshold.timestamp_s = 0;
	// active_threshold.timestamp_ms = 500000;

	pcap_file_header pfh;
	pcap_header ph;

	fread(&pfh, sizeof(pcap_file_header), 1, fp);
	// prinfPcapFileHeader(&pfh);
	printf("Start Analyze %s\n", argv[4]);
	for (count = 1;;++count){
		//read pcap header
		readSize = fread(&ph, sizeof(pcap_header), 1, fp);
		if (readSize <= 0)
			break;

		//read capture packet
		memset(buff, 0, MAX_ETH_FRAME);
		readSize = fread(buff, 1, ph.capture_len, fp);
		if (count == 1){
			start_ts.timestamp_s = ph.ts.timestamp_s;
			start_ts.timestamp_ms = ph.ts.timestamp_ms;
		}
		//ip header
		eth = 0;
		memcpy(ih, buff, 20);
		if (ih->ver_hlen != 0x45){
			eth += ETH_LENGTH;
			memcpy(ih, buff + ETH_LENGTH, 20);
		}

		// int pfx_index = find_pkt_pfx(pfx_set, set_size, ih, rib_root);
		unsigned long dst_ip = ntohl(ih->dst_ip);
		trie_node *tmp_node = trie_search(rib_root, ip_key_l(dst_ip));
		unsigned int tmp_pfx_ip = key_ip(tmp_node->pfx_key);
		int pfx_index = binary_search_ip(tmp_pfx_ip, pfx_set, set_size);
		if (pfx_index <= 0){
			continue;
		}

		if (ih->protocol == 6){
			//TCP packet
			int ih_len = (ih->ver_hlen & 0xf) << 2;
			memcpy(th, buff + ih_len + eth, 20);
			if ((th->flags & 0x10)==0 || (th->flags & 0x1)!=0){
				//SYN or FIN pkt
				continue;
			}

			int tcp_hlen = (th->header_len >> 4) << 2;

			if (pfx_set[pfx_index].current_bin_start_time.timestamp_s == 0 && pfx_set[pfx_index].current_bin_start_time.timestamp_ms == 0){
				pfx_set[pfx_index].current_bin_start_time.timestamp_s = ph.ts.timestamp_s;
				pfx_set[pfx_index].current_bin_start_time.timestamp_ms = ph.ts.timestamp_ms;
			}

			flow *tmp_f = (flow *)malloc(sizeof(flow));
			tmp_flow(tmp_f, ph, ih, th, eth);
			Bucket *bkt = search_ht(pfx_set[pfx_index].ht, tmp_f);
			if (ph.ts.timestamp_s - start_ts.timestamp_s >= RTT_MEASURE_TIME){
				float frac = update_sw(&pfx_set[pfx_index], ph.ts, bin, log_fp);
				if (frac >= 0.5 * pfx_set[pfx_index].thresh_p){
					//location
					int x;
					fprintf(suspect, "%u.%06u\t%f\t%f\t", ph.ts.timestamp_s, ph.ts.timestamp_ms, pfx_set[pfx_index].thresh_p, frac);
					fprintf(suspect, "%lu.%lu.%lu.%lu/%d\t", pfx_set[pfx_index].ip >> 24,
						(pfx_set[pfx_index].ip >> 16) & 0xff,
						(pfx_set[pfx_index].ip >> 8) & 0xff,
						pfx_set[pfx_index].ip & 0xff,
						pfx_set[pfx_index].slash);
					for (x = 0;x < 15;++x){
						if (tmp_node->path.nodes[x] != 0)
							fprintf(suspect,"%d ", tmp_node->path.nodes[x]);
					}
					fprintf(suspect,"\n");
				}
			}
			if (bkt){
				if (ph.ts.timestamp_s - start_ts.timestamp_s >= RTT_MEASURE_TIME){
					timestamp pkt_diff = ts_minus(ph.ts, bkt->f->last_active_time);
					if (ts_cmp(pkt_diff, window) >= 0){
						// int last_bin = (pfx_set[pfx_index].curr_sw_pos - 1) % BIN_NUM;
						pfx_set[pfx_index].active_flow_count_window[pfx_set[pfx_index].curr_sw_pos] += 1;
						bkt->f->last_active_time.timestamp_s = ph.ts.timestamp_s;
						bkt->f->last_active_time.timestamp_ms = ph.ts.timestamp_ms;
					}
				}
				//retransmission detection
				int pkt_data = ntohs(ih->total_len) - ih_len - eth - tcp_hlen;
				unsigned int current_expect_seq = ntohl(th->seq) + pkt_data;
				if (current_expect_seq == bkt->f->expect_seq &&
					current_expect_seq >= ntohl(th->seq) &&
					pkt_data > 0){//retransimission
					// printf("Time: %u.%u\n", ph.ts.timestamp_s, ph.ts.timestamp_ms);
					int keep_alive = 0;
					if ((pkt_data == 0 || pkt_data == 1) && (current_expect_seq == ntohl(th->seq) + 1)){
						keep_alive = 1;
					}
					if (ph.ts.timestamp_s - start_ts.timestamp_s >= RTT_MEASURE_TIME){
						timestamp rt_diff = ts_minus(ph.ts, bkt->f->last_rt_time);
						if (ts_cmp(rt_diff, window) >= 0 && keep_alive == 0){
							// int last_bin = (pfx_set[pfx_index].curr_sw_pos - 1) % BIN_NUM;
							pfx_set[pfx_index].sliding_window[pfx_set[pfx_index].curr_sw_pos] += 1;

							bkt->f->last_rt_time.timestamp_s = ph.ts.timestamp_s;
							bkt->f->last_rt_time.timestamp_ms = ph.ts.timestamp_ms;
							// if (pfx_set[pfx_index].ip == 1218304000){
							fprintf(frt,"Time: %u.%06u\t", ph.ts.timestamp_s, ph.ts.timestamp_ms);
							fprintf(frt,"Src_ip :%u.%u.%u.%u\t", ntohl(ih->src_ip) >> 24,
								(ntohl(ih->src_ip) >> 16) & 0xff,
								(ntohl(ih->src_ip) >> 8) & 0xff,
								ntohl(ih->src_ip) & 0xff);
							fprintf(frt,"Dst_ip :%lu.%lu.%lu.%lu\n", dst_ip >> 24,
								(dst_ip >> 16) & 0xff,
								(dst_ip >> 8) & 0xff,
								dst_ip & 0xff);
								// printf("%d %d %d\n", ph.len, ntohs(ih->total_len), pkt_data);
							// }
						}
						// if (pfx_set[pfx_index].ip == 839581696){
						// 	printf("Dst ip: %lu.%lu.%lu.%lu Time: %u.%u\n", dst_ip >> 24,
						// 		(dst_ip >> 16) & 0xff,
						// 		(dst_ip >> 8) & 0xff, 
						// 		dst_ip & 0xff, 
						// 		ph.ts.timestamp_s, 
						// 		ph.ts.timestamp_ms);
						// }
					}
				}
				else{
					if (ph.ts.timestamp_s - start_ts.timestamp_s < RTT_MEASURE_TIME){
					//rtt measure and threshold calculation at first
						unsigned int rtt = flight_update(bkt->f, tmp_f->last_ts);
						if (rtt){
							// fprintf(frtt,"%d\t", pfx_index);
							// fprintf(frtt,"Src %u.%u.%u.%u\t", bkt->f->src_ip >> 24,
							// 	(bkt->f->src_ip >> 16) & 0xff,
							// 	(bkt->f->src_ip >> 8) & 0xff,
							// 	bkt->f->src_ip & 0xff);
							// fprintf(frtt,"Dst %u.%u.%u.%u\t", bkt->f->dst_ip >> 24,
							// 	(bkt->f->dst_ip >> 16) & 0xff,
							// 	(bkt->f->dst_ip >> 8) & 0xff,
							// 	bkt->f->dst_ip & 0xff);
							// fprintf(frtt,"Src port: %u\t", bkt->f->src_port);
							// fprintf(frtt,"Dst port: %u\t", bkt->f->dst_port);
							// fprintf(frtt,"Rtt sample: %d\n", rtt);

							//simplified output:
							fprintf(frtt, "%lu.%lu.%lu.%lu_%d\t", pfx_set[pfx_index].ip >> 24,
								(pfx_set[pfx_index].ip >> 16) & 0xff,
								(pfx_set[pfx_index].ip >> 8) & 0xff,
								pfx_set[pfx_index].ip & 0xff,
								pfx_set[pfx_index].slash);
							fprintf(frtt, "%d\n", rtt);
						}
					}
					else{
						if (flag == 0){
							// printf("Rtt measurement complete.\n");
							if (frtt){
								fclose(frtt);
							}
							// system("python ./flow_stats.py");
							flag = 1;
							// printf("Calculating Thresholds.\n");
							int j = 0, p, q;
							// char *fn = (char *)malloc(100);
							for (;j < set_size;++j){
								// memset(fn, 0, 100);
								// int2filename(j, fn);
								char *fn = pfx2filename(&(pfx_set[j]));
								int line_num = file_line_num(fn);
								if (line_num == 0){
									continue;
								}

								float *dat = data_from_file(fn, line_num);
								float *Px = data_to_Px(dat, line_num);
								// printf("1\n");
								float *Py = Px_to_Py(Px, CDF_DATA_COUNT);
								float max_peak = 0;
								for (p = 0;p + 799 < CDF_DATA_COUNT;++p){
									float tmp = 0;
									for (q = p;q < p + 800;++q){
										tmp += Py[q];
									}
									if (tmp > max_peak){
										max_peak = tmp;
									}
								}
								if (max_peak <= 0.000001){
									max_peak = 0.5;
								}
								pfx_set[j].thresh_p = max_peak;
								if (dat){
									free(dat);
								}
								if (Px){
									free(Px);
								}
								if (Py){
									free(Py);
								}
								// printf("Pfx: %d, probability: %f\n", j, max_peak);
							}
							// printf("End Calculating Thresholds.\n");

						}
						//
						// timestamp tmp_ts;
						// tmp_ts.timestamp_s = ph.ts.timestamp_s - bkt->f->last_ts.timestamp_s;
						// tmp_ts.timestamp_ms = ph.ts.timestamp_ms - bkt->f->last_ts.timestamp_ms;
						// if (ts_cmp(tmp_ts, active_threshold) < 0){
						// 	bkt->f->is_active = 1;
						// }
						// else{
						// 	bkt->f->is_active = 0;
						// }

					}

				}
				bkt->f->last_ts.timestamp_s = ph.ts.timestamp_s;
				bkt->f->last_ts.timestamp_ms = ph.ts.timestamp_ms;
				bkt->f->expect_seq = current_expect_seq;
				free(tmp_f);

			}
			else{
				tmp_f->last_active_time.timestamp_s = ph.ts.timestamp_s;
				tmp_f->last_active_time.timestamp_ms = ph.ts.timestamp_ms;
				insert_ht(pfx_set[pfx_index].ht, tmp_f);
				// int last_bin = (pfx_set[pfx_index].curr_sw_pos - 1) % BIN_NUM;
				pfx_set[pfx_index].active_flow_count_window[pfx_set[pfx_index].curr_sw_pos] += 1;
			}

		}

	}

	printf("End Anlayzing.\n");
	if (buff)
		free(buff);
	if (fp)
		fclose(fp);
	if (log_fp)
		fclose(log_fp);
	if (suspect)
		fclose(suspect);
	if (frtt){
		fclose(frtt);
	}
	if (frt){
		fclose(frt);
	}

	
	//location

	
	return 0;
}