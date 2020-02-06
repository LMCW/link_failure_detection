#include "rtt.h"
#include "stdlib.h"

static inline int max(int a, int b){
	if (b > a) a = b;
	return a;
}

static inline void rtt_init(rtt_distribution *rd, int first_sample){
	rd->smooth_rtt = first_sample;
	rd->rtt_var = first_sample / 2;
	rd->rto = rd->smooth_rtt + max(G, 4 * rd->rtt_var);
	return;
}

void rtt_update(rtt_distribution *rd, int sample){
	if (rd->smooth_rtt == 0)
		rtt_init(rd, sample);
	rd->rtt_var = rd->rtt_var * 3 / 4 + abs(rd->smooth_rtt - sample) / 4;
	rd->smooth_rtt = rd->smooth_rtt * 7 / 8 + sample / 8;
	rd->rto = rd->smooth_rtt + max(G, 4 * rd->rtt_var);
	return;
}

int threshold_simulation(rtt_distribution *rd){
	return 0;
}