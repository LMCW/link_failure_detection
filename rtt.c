#include "rtt.h"
#include "math.h"

float max(float a, float b){
	if (b > a) a = b;
	return a;
}

void rtt_init(rtt_distribution *rd, float first_sample){
	rd->smooth_rtt = first_sample;
	rd->rtt_var = first_sample / 2.0;
	rd->rto = rd->smooth_rtt + max(G, 4 * rd->rtt_var);
	return;
}

void rtt_update(rtt_distribution *rd,float sample){
	if (rd->smooth_rtt == 0)
		rtt_init(rd, sample);
	rd->rtt_var = (1 - beta) * rd->rtt_var + beta * fabs(rd->smooth_rtt - sample);
	rd->smooth_rtt = (1 - alpha) * rd->smooth_rtt + alpha * sample;
	rd->rto = rd->smooth_rtt + max(G, 4 * rd->rtt_var);
	return;
}