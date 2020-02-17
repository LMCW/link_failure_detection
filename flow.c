#include "flow.h"
#include "stdio.h"
#include "stdlib.h"

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


int mod(int a,int b){
	int res = a % b;
	if (res < 0){
		res += b;
	}
	return res;
}

unsigned int flight_update(_flow *f, _timestamp ts){
	int current_iat = (ts.timestamp_s - f->last_ts.timestamp_s) * 1000000 +\
		(ts.timestamp_ms - f->last_ts.timestamp_ms);
	if (current_iat == 0){
		return 0;
	}
	if (f->iq.count == 0){
		iat_queue_enqueue(&(f->iq), current_iat);
		f->last_ts.timestamp_s = ts.timestamp_s;
		f->last_ts.timestamp_ms = ts.timestamp_ms;
		return 0;
	}
	unsigned int rtt_sample = 0;
	double g;
	int last_iat_pos = mod((f->iq.head - 1), MAX_RECORD_IAT_NUM);
	// printf("%d\n", last_iat_pos);
	if (f->iq.iat_array[last_iat_pos] == 0){
		g = 0;
		//abnormal case;
		int i = f->iq.tail, j;
		printf("Abnormal flow src: %u.%u.%u.%u\t", f->src_ip >> 24,
			(f->src_ip >> 16) & 0xff,
			(f->src_ip >> 8) & 0xff,
			f->src_ip & 0xff);
		printf("dst: %u.%u.%u.%u\t", f->dst_ip >> 24,
			(f->dst_ip >> 16) & 0xff,
			(f->dst_ip >> 8) & 0xff,
			f->dst_ip & 0xff);
		for (j = 0;j < f->iq.count;i = (i+1) % MAX_RECORD_IAT_NUM, j++){
			printf("%d ", f->iq.iat_array[i]);
		}
		printf("\n");
	}
	else{
		g = abs(current_iat - f->iq.iat_array[last_iat_pos]) / f->iq.iat_array[last_iat_pos];
	}
	if (g < G_THRESHOLD || current_iat < FLIGHT_THRESHOLD){
		f->flight_size += 1;
	}
	else{
		if (f->flight_size <= 3){
			//rtt_sample calculation
			int i,tmp;
			for (i=0;i < f->flight_size;++i){
				tmp = mod((last_iat_pos - i), MAX_RECORD_IAT_NUM);
				rtt_sample += f->iq.iat_array[tmp];
			}
			rtt_sample += current_iat;
		}
		f->flight_size = 0;
	}
	if (f->iq.count == MAX_RECORD_IAT_NUM){
		iat_queue_dequeue(&(f->iq));
	}
	iat_queue_enqueue(&(f->iq), current_iat);
	f->last_ts.timestamp_s = ts.timestamp_s;
	f->last_ts.timestamp_ms = ts.timestamp_ms;
	return rtt_sample;
}


/*
unsigned int flight_update(_flow *f, _timestamp ts){
	// printf("HAHAHA\n");
	int ms = (ts.timestamp_s - f->last_ts.timestamp_s) * 1000000 +\
		(ts.timestamp_ms - f->last_ts.timestamp_ms);
	int rtt_sample = 0;
	if (ms > FLIGHT_THRESHOLD){
		//judge if the flight size is smaller than 3
		int i, flight_size;
		for (i=f->iq.tail, flight_size = 0;;i = (i+1) % MAX_RECORD_IAT_NUM){
			if (f->iq.iat_array[i] <= FLIGHT_THRESHOLD){
				flight_size++;
				rtt_sample += f->iq.iat_array[i];
			}
			else{
				break;
			}
			if (i == f->iq.head){
				break;
			}
		}
		if (flight_size <= 3){
			rtt_sample += ms;
		}
		else{
			rtt_sample = 0;
		}
	}
	//iqt_queue enqueue
	if (f->iq.count == MAX_RECORD_IAT_NUM){
		iat_queue_dequeue(&(f->iq));
	}
	iat_queue_enqueue(&(f->iq), ms);
	f->last_ts.timestamp_s = ts.timestamp_s;
	f->last_ts.timestamp_ms = ts.timestamp_ms;
	return rtt_sample;
}
*/