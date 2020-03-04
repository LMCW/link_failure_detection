#ifndef timestamp_h
#define timestamp_h

typedef struct timestamp{
	unsigned int timestamp_s;
	unsigned int timestamp_ms;
}timestamp;

timestamp ts_minus(timestamp a, timestamp b);
int ts_divide(timestamp a, timestamp b);
int ts_cmp(timestamp a, timestamp b);

#endif