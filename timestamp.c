#include "timestamp.h"

timestamp ts_minus(timestamp a, timestamp b){
	timestamp res;
	//assert a > b
	if (a.timestamp_ms < b.timestamp_ms){
		res.timestamp_ms = a.timestamp_ms + 1000000 - b.timestamp_ms;
		res.timestamp_s = a.timestamp_s - 1 - b.timestamp_s;
	}
	else{
		res.timestamp_s = a.timestamp_s - b.timestamp_s;
		res.timestamp_ms = a.timestamp_ms - b.timestamp_ms;
	}
	return res;
}

int ts_divide(timestamp a, timestamp b){
	return (int)((a.timestamp_s * 1000000 + a.timestamp_ms) / (b.timestamp_s * 1000000 + b.timestamp_ms));
}

int ts_cmp(timestamp a, timestamp b){
	if (a.timestamp_s < b.timestamp_s) 
		return -1;
	else if (a.timestamp_s == b.timestamp_s){
		if (a.timestamp_ms < b.timestamp_ms)
			return -1;
		else if (a.timestamp_ms == b.timestamp_ms)
			return 0;
		else
			return 1;
	}
	else
		return 1;
}