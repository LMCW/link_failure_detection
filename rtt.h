#ifndef rtt_h
#define rtt_h

#define G 0.01
#define alpha 0.125
#define beta 0.25

typedef struct rtt_distribution{
	float smooth_rtt;
	float rtt_var;
	float rto;
}rtt_distribution;

void rtt_init(rtt_distribution *rd, float first_sample);

void rtt_update(rtt_distribution *rd, float sample);

#endif