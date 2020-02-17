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

if __name__ == '__main__':
	fn = raw_input('rtt file name: ')
	dic = rtt_distribution(fn)
	for key in dic:
		fk = open('./rtt/'+str(key)+'.txt', 'w')
		for i in dic[key]:
			fk.write(i+'\n')
		fk.close()

			