#ifndef monitor_h
#define monitor_h

#define MAX_QUEUE_LENGTH 50000
/*
500: 47s traffic    7s spent 27834 retransmission
10000: 47s traffic  8s spent 41345 retransmission
50000: 47s traffic  141s spent 306696 retransmission
100000: 47s traffic 859s spent 9117599 retransmission
*/

typedef unsigned int bpf_u_int32;
//in the flow defined here, a-->b is different from b-->a
typedef struct flow{
	bpf_u_int32 src;
	bpf_u_int32 dst;
	bpf_u_int32 src_p;
	bpf_u_int32 dst_p;
	bpf_u_int32 expect_seq;
	bpf_u_int32 curr_ack;
	bpf_u_int32 last_size;
}flow;

typedef struct FlowQueue{
	flow *queue;
	int head;
	int tail;
	int count;
	int size;
}FlowQueue;

int queue_init(FlowQueue *Q, int size);
int queue_free(FlowQueue *Q);
int queue_empty(FlowQueue * Q);
int queue_enqueue(FlowQueue *Q, flow *item);
int queue_dequeue(FlowQueue *Q);

int flow_match(bpf_u_int32 src, bpf_u_int32 dst, bpf_u_int32 src_p, bpf_u_int32 dst_p, flow f);
#endif