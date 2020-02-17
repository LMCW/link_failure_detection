#ifndef rtt_h
#define rtt_h

#define G 1000		//1000microsecond is 1millisecond

/*
Smooth rtt and rtt variation are in the same unit as timestamp_ms, microsecond 
*/
typedef struct rtt_distribution{
	int smooth_rtt;
	int rtt_var;
	int rto;
}rtt_distribution;



static inline int max(int a, int b);
static inline void rtt_init(rtt_distribution *rd, int first_sample);
void rtt_update(rtt_distribution *rd, int sample);
int threshold_simulation(rtt_distribution *rd);

#endif