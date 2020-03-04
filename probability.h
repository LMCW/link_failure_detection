#ifndef probability_h
#define probability_h

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "math.h"

#define CDF_DATA_COUNT 3000
#define DIFFERENTIAL_H 0.1

float* data_from_file(char *filename, int line_num);
float* data_to_cdf(float *data, int dat_num);
// float* cdf_to_pdf(float *cdf);
float str_to_float(char *number);
int file_line_num(char *filename);
float *data_to_Px(float *data, int dat_num);
float *Px_to_Py(float *Px, int dat_num);

// float simpson(float h, float a, float b, int N, float *y_arr, float (*func)(float*, float));
// float differential_3(float h, float x, float *y_arr,float (*func)(float *, float));

#endif