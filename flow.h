#ifndef flow_h
#define flow_h

#include "timestamp.h"
#include "iat.h"
#include "stdlib.h"
#include <arpa/inet.h>

#define FLIGHT_THRESHOLD 1000//10millisecond
#define G_THRESHOLD 10

typedef struct flow{
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int expect_seq;	
	//retransmission detection

	// int is_active;
	// int retransmission;//0 or 1
	timestamp last_rt_time;
	//TODO: flow active judgement

	iat_queue iq;
	int flight_size;
	//Rtt measurement

	timestamp last_ts;
	timestamp last_active_time;
}flow;

unsigned int flight_update(flow *f, timestamp ts);
int flow_match(unsigned int src, unsigned int dst, unsigned int src_p, unsigned int dst_p, flow f);

#endif