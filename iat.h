#ifndef iat_h
#define iat_h

#define MAX_RECORD_IAT_NUM 5

#include "stdio.h"

typedef struct iat_queue{
	int iat_array[MAX_RECORD_IAT_NUM];
	int head;
	int tail;
	int count;
}iat_queue;

void iat_queue_init(iat_queue *iq);
void iat_queue_enqueue(iat_queue *iq, int iat);
int iat_queue_empty(iat_queue *iq);
void iat_queue_dequeue(iat_queue *iq);
int _mod(int a,int b);

#endif