#include "iat.h"

void iat_queue_init(iat_queue *iq){
	iq->count = 0;
	iq->head = 0;
	iq->tail = 0;
	int i;
	for (i = 0;i < MAX_RECORD_IAT_NUM;++i){
		iq->iat_array[i] = 0;
	}
	return;
}

void iat_queue_enqueue(iat_queue *iq, int iat){
	if (iq->count >= MAX_RECORD_IAT_NUM){
		printf("Queue is full!!!\n");
		return;
	}
	iq->iat_array[iq->head] = iat;
	iq->head = (iq->head + 1) % MAX_RECORD_IAT_NUM;
	iq->count++;
	// printf("Enqueue %d\n", iat);
	return;
}

int iat_queue_empty(iat_queue *iq){
	return iq->count == 0;
}

void iat_queue_dequeue(iat_queue *iq){
	if (!iat_queue_empty(iq)){
		iq->tail = (iq->tail + 1) % MAX_RECORD_IAT_NUM;
		iq->count--;
	}
	else{
		printf("Empty Queue!!!\n");
	}
	return;
}

int _mod(int a,int b){
	int res = a % b;
	if (res < 0){
		res += b;
	}
	return res;
}