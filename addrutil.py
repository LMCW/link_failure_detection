import math
import os, sys

def ip_str2num(ip_addr):
	dat = ip_addr.split('.')
	ret = 0
	for i in [0,1,2,3]:
		ret += int(dat[i])<< ((3 - i) * 8)
	return ret

if __name__ == '__main__':
	ip_addr = raw_input("IP Address:")
	print ip_str2num(ip_addr)
