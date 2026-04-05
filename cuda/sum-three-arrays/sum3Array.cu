#include <stdio.h>
#include <cuda.h>
#include <time.h>
#include <stdlib.h>

__global__ void calculateSum(int* array1, int* array2, int* array3, int* array4,int count){
	int index = blockDim.x * blockIdx.x + threadIdx.x;
	array4[index] = array1[index] + array2[index] + array3[index];
}

int main(){
	int count = 1048576;
	int* array1 = (int*)malloc(count * sizeof(int));
	int* array2 = (int*)malloc(count * sizeof(int));
	int* array3 = (int*)malloc(count * sizeof(int));
	int* array4 = (int*)malloc(count * sizeof(int));
	for(int i = 0;i < count;i++){
		array1[i] = rand() % count;
		array2[i] = rand() % count;
		array3[i] = rand() % count;
	}
	clock_t start = clock();
	for(int i =0 ;i < count;i++){
		array4[i] = array1[i] + array2[i] + array3[i];
	}
	clock_t end = clock();
	double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("Diff %f\n", cpu_time_used );

	int* gpu1data;
	cudaMalloc(&gpu1data, count * sizeof(int));
	int* gpu2data;
	cudaMalloc(&gpu2data, count * sizeof(int));
	int* gpu3data;
	cudaMalloc(&gpu3data, count * sizeof(int));
	int* gpu4data;
	cudaMalloc(&gpu4data, count * sizeof(int));
	cudaMemcpy(gpu1data, array1, count* sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(gpu2data, array2, count* sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(gpu3data, array3, count* sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(gpu4data, array4, count* sizeof(int), cudaMemcpyHostToDevice);
	dim3 block(8192);
	dim3 grid(128);
	clock_t start1 = clock();
	calculateSum<<<grid,block>>>(gpu1data, gpu2data, gpu3data, gpu4data, count);
	cudaDeviceSynchronize();
	clock_t end1 = clock();
	cpu_time_used = ((double) (end1 - start1)) / CLOCKS_PER_SEC;
	printf("Diff %f\n", cpu_time_used );
}
