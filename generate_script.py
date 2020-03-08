#!/usr/bin/python
import os, sys

"""
Case
./pcaptest 
./as-rel/20130501.as-rel.txt 
./ribs/2013/dedup_simple_rib_eqix.txt 
./prefix/2013/prefix_0529-125710.txt 
./trace_caida/2013/equinix-chicago.dirA.20130529-125710.UTC.anon.pcap
"""
def generate_script(pcap_dir):
	fsh = open('run.sh','w')
	filenames = os.listdir(pcap_dir)
	for fn in filenames:
		if ('pcap' not in fn) or ('dirB' in fn):
			continue
		tmp = fn.split('.')
		pcap_time = tmp[2]
		fsh.write('./pcaptest ./as-rel/20130501.as-rel.txt ./ribs/2013/dedup_simple_rib_eqix.txt ./prefix/2013/prefix_'
			+ pcap_time+'.txt ./trace_caida/2013/' + fn + '\n')
	fsh.close()

if __name__ == '__main__':
	generate_script('./trace_caida/2013/')

