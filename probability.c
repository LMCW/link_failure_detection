#include "probability.h"

float str_to_float(char *number){
	float integer = 0.0;
	float decimal = 0.0;
	int num_len = strlen(number);
	int flag = 0, i, j;
	for (i = 0;i < num_len;++i){
		if (number[i] == '.'){
			break;
		}
		integer = integer * 10 + (number[i] - '0');
	}
	for (j = num_len - 1;j > i;j--){
		if (number[j] < '0' || number[j] > '9'){
			continue;
		}
		decimal = decimal / 10 + (number[j]-'0');
	}
	decimal /= 10;
	return integer+decimal;
}

int file_line_num(char *filename){
	int ret = 0;
	char buff[100];
	FILE *fp = fopen(filename, "r");
	if (!fp){
		// printf("No file %s", filename);
		return 0;
	}
	while (!feof(fp)){
		memset(buff, 0, 100);
		fgets(buff, 100, fp);
		ret += 1;
	}
	fclose(fp);
	return ret;
}

float* data_from_file(char *filename, int line_num){
	FILE *fp = fopen(filename, "r");
	char buff[100];
	int i = 0;
	// printf("Line Num: %d\n", line_num);
	float *data = NULL;
	data = (float *)malloc(sizeof(float) * line_num);
	while (!feof(fp)){
		memset(buff, 0, 100);
		fgets(buff, 100, fp);
		data[i] = str_to_float(buff);
		i += 1;
	}
	fclose(fp);
	return data;
}

int cmp(const void *a, const void *b){
	if (*((float *)a) < *((float *)b))
		return -1;
	else if (*((float *)a) == *((float *)b))
		return 0;
	else
		return 1;
}

float* data_to_cdf(float *data, int dat_num){
	qsort(data, dat_num, sizeof(float), cmp);
	float tmp;
	float *cdf = NULL;
	cdf = (float *)malloc(sizeof(float) * CDF_DATA_COUNT);
	int count_array[CDF_DATA_COUNT];
	memset(count_array, 0, sizeof(int) * CDF_DATA_COUNT);
	int i, total;
	for (i = 0, total = 0;i < dat_num;++i){
		if (data[i] > CDF_DATA_COUNT - 1)
			continue;
		count_array[(int)data[i]] += 1;
		total += 1;
	}
	for (i = 0;i < CDF_DATA_COUNT;++i){
		tmp += (float)count_array[i] / (float)total;
		if (tmp > 1)
			tmp = 1.0;
		cdf[i] = tmp;
	}
	// free(count_array);
	return cdf;
}

float *data_to_Px(float *data, int dat_num){
	qsort(data, dat_num, sizeof(float), cmp);
	float tmp;
	float *Px = NULL;
	Px = (float *)malloc(sizeof(float) * CDF_DATA_COUNT);
	memset(Px, 0, sizeof(float) * CDF_DATA_COUNT);
	int count_array[CDF_DATA_COUNT];
	memset(count_array, 0, sizeof(int) * CDF_DATA_COUNT);
	int i, total;
	for (i = 0, total = 0;i < dat_num;++i){
		if (data[i] > CDF_DATA_COUNT - 1)
			continue;
		count_array[(int)data[i]] += 1;
		total += 1;
	}
	for (i = 0;i < CDF_DATA_COUNT;++i){
		Px[i] = (float)count_array[i] / (float)total;
	}
	// free(count_array);
	return Px;
}

float *Px_to_Py(float *Px, int dat_num){
	float *Py = (float *)malloc(sizeof(float) * CDF_DATA_COUNT);
	int i, j;
	Py[0] = 0;
	// printf("HAHA\n");
	for (i = 1;i < dat_num;++i){
		Py[i] = 0;
		// printf("%d\n", i);
		for (j = i;j < CDF_DATA_COUNT;++j){
			Py[i] += Px[j]/j;
		}
	}
	return Py;
}

