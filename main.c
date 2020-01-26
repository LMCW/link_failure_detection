#include "pcap.h"
#include "prefix.h"

int main(int argc, char const *argv[])
{
	int ret;
	ret = loadPcap();
	// prefix_set S;
	// init(&S, 100000);
	// ret = generateSet(&S,16);
	return ret;
}