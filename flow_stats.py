import numpy as np
import matplotlib.pyplot as plt
import math

def flow_distribution():
	fc = []
	f = open('flow_stats.txt')
	contents = f.readlines()
	for line in contents:
		line = line.strip('\n')
		tmp = line.split('\t')
		if int(tmp[2]) != 0:
			fc.append(int(tmp[2]))
	fc = sorted(fc)
	lg = lambda x:math.log(x, 10)
	fc = [lg(i) for i in fc]
	x = range(len(fc))
	plt.xlabel('pfx')
	plt.ylabel('log-flow_count')
	plt.plot(x,fc)
	plt.show()

# flow_distribution()
"""
def rtt_distribution(fn):
	fd = open(fn, 'r')
	contents = fd.readlines()
	res = {}
	for line in contents:
		li = line.strip('\n').split('\t')
		pfx = li[0]
		rtt_sample = li[-1].split(' ')[2]
		if pfx in res:
			res[pfx].append(rtt_sample)
		else:
			res[pfx] = [rtt_sample]
	fd.close()
	return res
"""

def rtt_distribution(fn):
	fd = open(fn, 'r')
	res = {}
	contents = fd.readlines()
	for line in contents:
		arr = line.strip('\n').split('\t')
		pfx = arr[0]
		rtt_sample = int(arr[1])
		if pfx in res:
			res[pfx].append(rtt_sample)
		else:
			res[pfx] = [rtt_sample]
	fd.close()
	return res

def generate_data(fn):
	dic = rtt_distribution(fn)
	for key in dic:
		# tmp_arr = []
		fk = open('./rtt/'+key+'_rtt.txt','w')
		for i in dic[key]:
			fk.write(str(i / 1000.0) + '\n')
		fk.close()
"""
def generate_data(fn):
	dic = rtt_distribution(fn)
	for key in dic:
		tmp_arr = []
		fk = open('./rtt/'+str(key)+'.txt', 'w')
		for i in dic[key]:
			fk.write(str(int(i)/1000.0)+'\n')
			tmp_arr.append(int(i)/1000.0)
		tmp_arr = sorted(tmp_arr)
		length = len(tmp_arr)
		if length < 10:
			continue
		x = range(length)
		# plt.ylabel('RTT-ms')
		# plt.plot(x, tmp_arr)
		# plt.savefig('./rtt/'+str(key)+'.png')
		# plt.clf()
		fk.close()
"""

def raw_to_cdf(fn):
	if "txt" not in fn:
		return None
	fin = open(fn, 'r')
	contents = fin.readlines()
	dat_arr = []
	min_rtt = 10000.0
	max_rtt = 0.0
	for line in contents:
		tmp = float(line.strip('\n'))
		if tmp > 3000.0 or tmp < 10:
			continue
		dat_arr.append(tmp)
		if tmp < min_rtt:
			min_rtt = tmp
		if tmp > max_rtt:
			max_rtt = tmp
	dat_arr = sorted(dat_arr)
	print min_rtt, max_rtt
	N = int(raw_input("Set N:"))
	h = (max_rtt - min_rtt) / N
	x = []
	y = [0 for i in range(N + 1)]
	for i in range(N + 1):
		x.append(min_rtt + i * h)
	total = 0.0
	for i in dat_arr:
		shift = int((i - min_rtt) / h)
		total += 1.0
		y[shift] += 1
	cdf = 0.0
	for i in range(N + 1):
		cdf += (y[i] / total)
		y[i] = cdf
		
	print y
	# plt.plot(x, y)
	# plt.show()
	fin.close()
	return x, y

def draw_prefix_flow_number(filename):
	f = open(filename, 'r')
	contents = f.readlines()
	array = []
	for line in contents:
		cont = line.strip('\n').split('\t')
		array.append(int(cont[-1]))
	return array

def draw_prefix_size(filename):
	f = open(filename, 'r')
	contents = f.readlines()
	array = []
	for line in contents:
		cont = line.strip('\n').split('\t')
		size = cont[-1].split(' ')
		array.append(int(size[-1]))
	return array

if __name__ == '__main__':
	# fn = raw_input("pfn file: ")
	# arr_1 = draw_prefix_flow_number("/Users/chenzp/Documents/Research/link_failure_detection/trace_caida/2015/flow_stats_2015_1.txt")
	# # fn = raw_input("pfs file: ")
	# arr_2 = draw_prefix_size("/Users/chenzp/Documents/Research/link_failure_detection/flow_size/2015_1.txt")
	# x_1 = range(len(arr_1))
	# x_2 = range(len(arr_2))
	# for i in x_1:
	# 	if arr_1[i] < 10 and arr_2[i] > 100000:
	# 		print i, arr_1[i], arr_2[i]
	# plt.plot(x_1, arr_1)
	# plt.plot(x_2, arr_2)
	# plt.show()
	# x, y = raw_to_cdf(fn)
	generate_data('./rtt_sample.txt')

			