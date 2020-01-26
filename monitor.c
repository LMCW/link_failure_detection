#include "monitor.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int queue_init(FlowQueue *Q, int size){
	Q->head = 0;
	Q->tail = 0;
	Q->count = 0;
	Q->queue = (flow *)malloc(size * sizeof(flow));
	if (Q->queue){
		Q->size = size;
		return 1;
	}
	else{
		Q->size = 0;
		fprintf(stderr, "Queue init failed\n");
		return 0;
	}
}

int queue_free(FlowQueue *Q){
	free(Q->queue);
	Q->head = 0;
	Q->tail = 0;
	Q->count = 0;
	Q->size = 0;
	Q->queue = NULL;
	return 1;
}

int queue_empty(FlowQueue * Q) {
    if (Q->count == 0)
        return 1;
    else 
    	return 0;
}

int queue_enqueue(FlowQueue *Q, flow *item){
	if (Q->count > Q->size)
		return -1;

	memcpy(&(Q->queue[Q->head]), item, sizeof(flow));
	// printf("Enqueue flow src: %u, dst:%u\n", Q->queue[Q->head].src, Q->queue[Q->head].dst);
	// if (Q->size == Q->count + 1)
	// 	printf("Enqueue: %u %u %u\n", Q->head,Q->queue[Q->head].src, Q->queue[Q->head].dst);
	Q->head = (Q->head + 1) % Q->size;
	Q->count++;
	return 1;
}

int queue_dequeue(FlowQueue *Q){
	if (!queue_empty(Q)){
		// *item = Q->queue[Q->tail];
		// printf("Dequeue: %u %u %u\n", Q->tail, Q->queue[Q->tail].src, Q->queue[Q->tail].dst);
		Q->tail = (Q->tail + 1) % Q->size;
		Q->count--;
		return 1;
	}
	return 0;
}

int flow_match(bpf_u_int32 src, bpf_u_int32 dst, bpf_u_int32 src_p, bpf_u_int32 dst_p, flow f){
	// printf("Cmp: src:%u dst:%u <===> flow src:%u dst:%u\n", src, dst, f.src, f.dst);
	if (src == f.src && dst == f.dst && src_p == f.src_p && dst_p == f.dst_p){
		return 1;
	}
	else
		return 0;
}



