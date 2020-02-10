import math
import random
import matplotlib.pyplot as plt
import numpy as np

def rand_rto(miu, sigma, times):
	a1 = np.random.normal(loc=miu, scale=sigma)
	srtt = []
	rttvar = []
	s_old = a1
	rttv0 = a1 * 0.5
	for i in range(times):
		n_rtt = np.random.normal(loc=miu, scale=sigma)
		if n_rtt < 0:
			n_rtt = 0
		rttv0 = 0.75 * rttv0 + 0.25 * math.fabs(n_rtt - s_old)
		s_old = 0.875 * s_old + 0.125 * n_rtt
		srtt.append(s_old)
		rttvar.append(rttv0)
	rto = s_old + 4 * rttv0
	return rto


def simulation(flownumber, miu_l, miu_r, sigma_l, sigma_r):
	rt_time = []
	for i in range(flownumber):
		#only one peak
		if miu_l == miu_r:
			rtt_miu = miu_l
		else:
			rtt_miu = random.uniform(miu_l, miu_r)
		if sigma_l == sigma_r:
			rtt_sigma = sigma_l
		else:
			rtt_sigma = random.uniform(sigma_l,sigma_r)
		# rtt_miu = random.uniform(500,500)
		# rtt_miu = 900
		# rtt_sigma = random.uniform(400,500)
		# rtt_sigma = 100
		if rtt_sigma >= rtt_miu:
			rtt_sigma = rtt_miu
		curr_rtt = np.random.normal(loc=rtt_miu, scale=rtt_sigma)
		if curr_rtt < 0:
			curr_rtt = random.uniform(0, rtt_miu);
		start_time = random.uniform(0, curr_rtt)
		rto = rand_rto(rtt_miu, rtt_sigma, times=1000)
		# print start_time + rto

		rt_time.append(start_time+rto)

	s_bin = 80
	n_bin = 25
	y = [0 for i in range(n_bin)]
	z = []
	for i in range(n_bin):
		z.append(i * s_bin)
	for i in rt_time:
		for j in range(n_bin):
			if i >= z[j] and i < z[j] + s_bin:
				y[j] += 1

	sw_sum = 0
	count = 0
	max_sw_sum = -1
	for i in range(n_bin):
		sw_sum += y[i]
		count += 1
		if count == 9:
			sw_sum -= y[i-8]
			count -= 1
		if sw_sum > max_sw_sum:
			max_sw_sum = sw_sum
	return max_sw_sum
	# plt.plot(z,y)
	# plt.show()

# def factorial(n):
# 	result = 1
# 	for i in range(2,n+1):
# 		result = result * i
# 	return result

def comb(n,m):
	return math.factorial(n)/(math.factorial(n-m)*math.factorial(m))

def probability(M, N, p):
	sp = 0.0
	for i in range(M, N + 1):
		tmp = comb(N,i) * (p**i) * ((1-p)**(N-i))
		# print tmp
		sp += tmp
	return sp

def trial(miu, div, flownumber):
	if miu <= 0 or div <= 1:
		return
	sigma_max = miu / 2
	sigma_min = 1
	step = (sigma_max - sigma_min) / (div - 1)
	f = open('sliding_window_simulation_result_'+str(miu)+'.txt','w')
	for i in range(div):
		sigma = sigma_min + i * step
		min_max_sw_sum = flownumber
		for j in range(1000):
			max_sw_sum = simulation(flownumber, miu, miu, sigma, sigma)
			if max_sw_sum < min_max_sw_sum:
				min_max_sw_sum = max_sw_sum
		f.write(str(miu)+'\t'+str(sigma)+'\t'+str(min_max_sw_sum)+'\n')
	f.close()

if __name__ == '__main__':
	# succ = 0
	# for i in range(1000):
	# 	a = simulation(100)
	# 	if a > 49:
	# 		succ += 1
	# print succ/1000.0
	# print(probability(50,100,0.5))
	# for j in range(12):
	# 	freq = []
	# 	flownumber = 100
	# 	succ = 0
	# 	# print "Std:",100+j*40 
	# 	# print "RTT miu:", 100+100*j
	# 	sigma = 30+j*10
	# 	miu = 450
	# 	for i in range(1000):
	# 		a = simulation(flownumber, miu, miu, sigma, sigma)
	# 		freq.append((a+0.0)/flownumber)
	# 		if a > (flownumber / 2 - 1):
	# 			succ += 1
	# 	print "miu left, miu right, sigma left, sigma right", miu, miu, sigma, sigma
	# 	print "The std of frequency is:", np.std(np.array(freq))
	# 	# print "The mean of frequency is:", np.mean(np.array(freq))
	# 	print "The minimum of frequency is", min(freq)
	# 	print "The median of frequency is:", np.median(np.array(freq))
	# 	print "The probability that sum is larger than half of the total is", probability(flownumber / 2, flownumber, np.median(np.array(freq)))
	# 	print "Success:", succ
	for i in range(11):
		miu = 300 + 50 * i
		trial(miu, 10, 100)
