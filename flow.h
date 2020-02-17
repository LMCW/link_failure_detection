#ifndef flow_h
#define flow_h

#define MAX_RECORD_IAT_NUM 5
#define FLIGHT_THRESHOLD 1000//10millisecond
#define G_THRESHOLD 10

typedef struct _timestamp{
	unsigned int timestamp_s;
	unsigned int timestamp_ms;
}_timestamp;

typedef struct iat_queue{
	//iat_queue has a fixed max size MAX_RECORD_IAT_NUM
	int iat_array[MAX_RECORD_IAT_NUM];
	int head;
	int tail;
	int count;
}iat_queue;

typedef struct _flow{
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int expect_seq;
	iat_queue iq;
	int flight_size;
	_timestamp last_ts;
}_flow;


void iat_queue_init(iat_queue *iq);
void iat_queue_enqueue(iat_queue *iq, int iat);
int iat_queue_empty(iat_queue *iq);
void iat_queue_dequeue(iat_queue *iq);

int mod(int a,int b);

unsigned int flight_update(_flow *f, _timestamp ts);

#endif