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

flow_distribution()
