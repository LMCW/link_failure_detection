#include "pcap.h"
#include "iat.h"

void prinfPcapFileHeader(pcap_file_header *pfh){
	if (pfh == NULL) return;
	printf("===============\n"
		"magic:0x%0x\n"
		"version_major:%u\n"
		"version_minor:%u\n"
		"thiszone:%d\n"
		"sigfigs:%u\n"
		"snaplen:%u\n"
		"linktype:%u\n"
		"===============\n",
		pfh->magic,
		pfh->version_major,
		pfh->version_minor,
		pfh->thiszone,
		pfh->sigfigs,
		pfh->snaplen,
		pfh->linktype);
	return;
}

void printfPcapHeader(pcap_header *ph){
	if (ph==NULL) return;
	printf("===============\n"
		"ts.timestamp_s:%u\n"
		"ts.timestamp_ms:%u\n"
		"capture_len:%u\n"
		"len:%d\n"
		"===============\n",
		ph->ts.timestamp_s,
		ph->ts.timestamp_ms,
		ph->capture_len,
		ph->len);
	return;
}

void tmp_flow(flow *f, pcap_header ph, ip_header *ih, tcp_header *th, int eth){
	int ih_len = (ih->ver_hlen & 0xf) << 2;
	int tcp_hlen = (th->header_len >> 4) << 2;
	f->src_ip = ntohl(ih->src_ip);
	f->dst_ip = ntohl(ih->dst_ip);
	f->src_port = th->src_port;
	f->dst_port = th->dst_port;
	f->expect_seq = ntohl(th->seq) + ntohs(ih->total_len) - ih_len - eth - tcp_hlen;
	f->flight_size = 0;
	f->is_active = 1;
	f->last_ts.timestamp_s = ph.ts.timestamp_s;
	f->last_ts.timestamp_ms = ph.ts.timestamp_ms;
	iat_queue_init(&(f->iq));
}