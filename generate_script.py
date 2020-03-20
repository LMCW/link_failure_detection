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
	filenames.sort()
	fsh.write(r"start_time=$(date +%s)")
	fsh.write('\n')
	for fn in filenames:
		if ('pcap' not in fn) or ('dirB' in fn) or ('gz' in fn) or ('stats' in fn):
			continue
		tmp = fn.split('.')
		pcap_time = tmp[2]
		fsh.write('./pcaptest ./as-rel/20130501.as-rel.txt ./ribs/2013/rib.20130620.1200_dedup.txt ./prefix/2013/prefix_'
			+ pcap_time+'.txt ./trace_caida/2013/' + fn + '\n')
	fsh.write(r"end_time=$(date +%s)")
	fsh.write('\n')
	fsh.write("cost_time=$[ $end_time-$start_time ]\n")
	fsh.write('echo "build kernel time is $(($cost_time/60))min $(($cost_time%60))s"\n')
	fsh.close()

def generate_analyze_script(suspect_dir):
	fsh = open('analyze.sh','w')
	filenames = os.listdir(suspect_dir)
	filenames.sort()
	fsh.write(r"start_time=$(date +%s)")
	fsh.write('\n')	
	for fn in filenames:
		if 'suspect' not in fn:
			continue
		#filename example suspect_0529-125900.txt
		#prefix file example prefix_20130529-125800
		arr = fn[8:20].split('-')
		date = arr[0]
		hm = arr[1]
		data_time = fn[8:20]
		fsh.write('./pcaptest ./as-rel/20130501.as-rel.txt ./ribs/2013/rib.20130620.1200_dedup.txt ./prefix/2013/prefix_2013'
			+ data_time +'.txt ./suspect/2013/' + date + '/' + 'pfx-route-' + hm + '.txt\n')
	fsh.write(r"end_time=$(date +%s)")
	fsh.write('\n')
	fsh.write("cost_time=$[ $end_time-$start_time ]\n")
	fsh.write('echo "build kernel time is $(($cost_time/60))min $(($cost_time%60))s"\n')
	fsh.close()

if __name__ == '__main__':
	# generate_script('./trace_caida/2013/')
	generate_analyze_script('./suspect/2013/0620')

