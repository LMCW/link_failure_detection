#ifndef pcap_h
#define pcap_h

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>
#include "hash_table.h"
#include "rtt.h"

typedef unsigned int bpf_u_int32;
typedef unsigned short u_short;
typedef int bpf_int32;
typedef unsigned char u_int8;
/*
500: 47s traffic    7s spent 27834 retransmission
10000: 47s traffic  8s spent 41345 retransmission
50000: 47s traffic  141s spent 306696 retransmission
100000: 47s traffic 859s spent 9117599 retransmission
*/
#define MAX_ETH_FRAME 1514
#define ERROR_FILE_OPEN_FAILED -1
#define ERROR_MEM_ALLOC_FAILED -2
#define ERROR_PCAP_PARSE_FAILED -3
#define ETH_LENGTH 14
#define BIN_NUM 10
#define BIN_TIME 0.08
/*
pcap file header 24B
Magic:4B:0X1A 2B 3C 4D:the beginning of the file
Major:2B:0X20 00: the main version of the file
Minor:2B:0X04 00: the side version of the file
ThisZone:4B:standard time: all zero
SigFIg:4B:the accuracy of timestamp:all zero
SnapLen:4Bthe max storage length
LinkType:4Bthe type of link
  0 BSD loopback devices
  1 Ethernet, and linux loopback devices
  6 802.5 token ring
  etc.
*/
typedef struct pcap_file_header{
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;
	bpf_u_int32 sigfigs;
	bpf_u_int32 snaplen;
	bpf_u_int32 linktype;
}pcap_file_header;

/*
Packet structure
Timestamp: the begin part of the timestamp
Timestamp: the end part of the timestamp
caplen: the length of the data
len: the real length of the data, often, len equals to caplen
packet data:data zone
*/

typedef struct timestamp{
	bpf_u_int32 timestamp_s;
	bpf_u_int32 timestamp_ms;	
}timestamp;

typedef struct pcap_header{
	timestamp ts;
	bpf_u_int32 capture_len;
	bpf_u_int32 len;
}pcap_header;

/*
IP header
*/
typedef struct ip_header{
	u_int8 ver_hlen;
	u_int8 tos;
	u_short total_len;
	u_short ID;
	u_short flag_segment;
	u_int8 ttl;
	u_int8 protocol;
	u_short checksum;
	bpf_u_int32 src_ip;
	bpf_u_int32 dst_ip;
}ip_header;

/*
tcp header
*/
typedef struct tcp_header{
	u_short src_port;
	u_short dst_port;
	bpf_u_int32 seq;
	bpf_u_int32 ack;
	u_int8 header_len;
	u_int8 flags;
	u_short window;
	u_short checksum;
	u_short urgentpointer;	
}tcp_header;

typedef struct prefix{
	unsigned long ip;
	int slash;
	int *sliding_window;
	/*sliding window should be a ring containing BIN_NUM bins
	  update window needs to figure out the shift number
	  remove bins from curr_sw_pos to (curr_sw_pos + shift) % BIN_NUM
	  curr_sw_pos = (curr_sw_pos + shift) % BIN_NUM; which is the new start of the sliding window
	  we should always add the rt to the last bin, which is (curr_sw_pos - 1) % BIN_NUM
	  current_bin_start_time += shift * BIN_TIME
	*/
	int curr_sw_pos;
	timestamp current_bin_start_time;
	hash_table *ht;
}prefix;

int flow_match(bpf_u_int32 src, bpf_u_int32 dst, bpf_u_int32 src_p, bpf_u_int32 dst_p, flow f);


prefix *pfx_set_from_file(int size);
int ip_pfx_match(unsigned long ip, prefix pfx);
int binary_search_ip(unsigned long ip, prefix *pfx_set, int set_size);
void monitor();
timestamp ts_minus(timestamp a, timestamp b);
int ts_divide(timestamp a, timestamp b);
int ts_cmp(timestamp a, timestamp b);

void prinfPcapFileHeader(pcap_file_header *pfh);
void printfPcapHeader(pcap_header *ph);
// void printPcap(void *data, int size);
unsigned long get_dst_ip(void *data);

int pfx_cmp(const void *a, const void *b);
void update_sw(prefix *pfx, timestamp packet_time, timestamp bin, FILE *fp);

#endif