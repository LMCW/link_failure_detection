#include "flow.h"

unsigned int flight_update(flow *f, timestamp ts){
	int current_iat = (ts.timestamp_s - f->last_ts.timestamp_s) * 1000000 +\
		(ts.timestamp_ms - f->last_ts.timestamp_ms);
	if (current_iat == 0){
		return 0;
	}
	if (f->iq.count == 0){
		iat_queue_enqueue(&(f->iq), current_iat);
		f->last_ts.timestamp_s = ts.timestamp_s;
		f->last_ts.timestamp_ms = ts.timestamp_ms;
		return 0;
	}
	unsigned int rtt_sample = 0;
	double g;
	int last_iat_pos = _mod((f->iq.head - 1), MAX_RECORD_IAT_NUM);
	// printf("%d\n", last_iat_pos);
	if (f->iq.iat_array[last_iat_pos] == 0){
		g = 0;
		//abnormal case;
		// int i = f->iq.tail, j;
		// printf("Abnormal flow src: %u.%u.%u.%u\t", f->src_ip >> 24,
		// 	(f->src_ip >> 16) & 0xff,
		// 	(f->src_ip >> 8) & 0xff,
		// 	f->src_ip & 0xff);
		// printf("dst: %u.%u.%u.%u\t", f->dst_ip >> 24,
		// 	(f->dst_ip >> 16) & 0xff,
		// 	(f->dst_ip >> 8) & 0xff,
		// 	f->dst_ip & 0xff);
		// for (j = 0;j < f->iq.count;i = (i+1) % MAX_RECORD_IAT_NUM, j++){
		// 	printf("%d ", f->iq.iat_array[i]);
		// }
		// printf("\n");
	}
	else{
		g = abs(current_iat - f->iq.iat_array[last_iat_pos]) / f->iq.iat_array[last_iat_pos];
	}
	if (g < G_THRESHOLD || current_iat < FLIGHT_THRESHOLD){
		f->flight_size += 1;
	}
	else{
		if (f->flight_size <= 3){
			//rtt_sample calculation
			int i,tmp;
			for (i=0;i < f->flight_size;++i){
				tmp = _mod((last_iat_pos - i), MAX_RECORD_IAT_NUM);
				rtt_sample += f->iq.iat_array[tmp];
			}
			rtt_sample += current_iat;
		}
		f->flight_size = 0;
	}
	if (f->iq.count == MAX_RECORD_IAT_NUM){
		iat_queue_dequeue(&(f->iq));
	}
	iat_queue_enqueue(&(f->iq), current_iat);
	f->last_ts.timestamp_s = ts.timestamp_s;
	f->last_ts.timestamp_ms = ts.timestamp_ms;
	return rtt_sample;
}

int flow_match(unsigned int src, unsigned int dst, unsigned int src_p, unsigned int dst_p, flow f){
	if (ntohl(src) == f.src_ip && ntohl(dst) == f.dst_ip && src_p == f.src_port && dst_p == f.dst_port){
		return 1;
	}
	else
		return 0;
}