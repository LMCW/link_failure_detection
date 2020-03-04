import sys,os

def link_failure_location(fn):
	fd = open(fn, "r")
	contents = fd.readlines()
	link_set = {}
	for li in contents:
		line_arr = li.strip(' \n').split('\t')
		ts = line_arr[0]
		path = line_arr[1]
		plk = path2link(path)
		for lk in plk:
			if link_set.has_key(lk):
				link_set[lk] += 1
			else:
				link_set[lk] = 1
	for key in link_set:
		print key, link_set[key]
	fd.close()

def path2link(path):
	res = []
	as_set = path.split(' ')
	set_size = len(as_set)
	for i in range(0, set_size - 1):
		a = int(as_set[i])
		b = int(as_set[i + 1])
		res.append(str(a)+'_'+str(b))
	return res

if __name__ == '__main__':
	# link_failure_location('./suspect_path.txt')
	link_failure_location('trial.txt')