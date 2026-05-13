#include <stdio.h>
#include <cuda.h>

__global__ void hello_world(int* array1, int* array2, int* array3, int sz){
	int index = blockIdx.x * blockDim.x + threadIdx.x;
	array3[index] = array1[index] + array2[index];
}

int main(){
	dim3 grid(8,1,1);
	dim3 block(8,1,1);
	int count = 64;
	int* cpuArray1 = (int*)malloc(count * sizeof(int));
	int* cpuArray2 = (int*)malloc(count * sizeof(int));
	int* cpuArray3 = (int*)malloc(count * sizeof(int));
	for(int i =0;i<64;i++){
		cpuArray1[i] = i;
		cpuArray2[i] = i;
	}
	int *gpuArray1;
	cudaMalloc(&gpuArray1, count*sizeof(int));
	int *gpuArray2;
	cudaMalloc(&gpuArray2, count*sizeof(int));
	int *gpuArray3;
	cudaHostAlloc(&gpuArray3, count*sizeof(int), cudaHostAllocMapped);
	int *dptr;
	cudaHostGetDevicePointer(&dptr, gpuArray3, 0);	
	cudaMemcpy(gpuArray1, cpuArray1, count * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(gpuArray2, cpuArray2, count * sizeof(int), cudaMemcpyHostToDevice);
	hello_world<<<grid,block>>>(gpuArray1, gpuArray2, gpuArray3, count);
	cudaDeviceSynchronize();
	//cudaMemcpy(cpuArray3, gpuArray3, count * sizeof(int), cudaMemcpyDeviceToHost);
	for(int i = 0;i<64;i++){
		printf("%d \n",dptr[i]);
	}
}
