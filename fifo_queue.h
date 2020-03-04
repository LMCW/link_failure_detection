#ifndef fifo_queue_h
#define fifo_queue_h

typedef struct fifo_queue{
	int *data;
	int head;
	int tail;
	int count;
}fifo_queue;

void fifo_queue_init(fifo_queue *fq);
void fifo_queue_enqueue(fifo_queue *fq, int num);
int fifo_queue_empty(fifo_queue *fq);
void fifo_queue_dequeue(fifo_queue *fq);

#endif