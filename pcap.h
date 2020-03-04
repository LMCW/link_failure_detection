#ifndef pcap_h
#define pcap_h

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>
#include "timestamp.h"
#include "flow.h"

typedef unsigned int bpf_u_int32;
typedef unsigned short u_short;
typedef int bpf_int32;
typedef unsigned char u_int8;

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


void prinfPcapFileHeader(pcap_file_header *pfh);
void printfPcapHeader(pcap_header *ph);
void tmp_flow(flow *f, pcap_header ph, ip_header *ih, tcp_header *th, int eth);


#endif