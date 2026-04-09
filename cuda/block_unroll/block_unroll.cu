#include <stdio.h>
#include <cuda.h>

__global__ void fun(int* a,int* b, int *c, int sz){
	int threadId = threadIdx.x + blockIdx.x * blockDim.x;
	c[threadId] = a[threadId] + b[threadId];
}

__global__ void fun_block_unroll(int* a,int* b, int *c, int sz){
	int threadId = (threadIdx.x + blockIdx.x * blockDim.x);
	if(threadId + 3 < sz){
		a[threadId] = b[threadId] + c[threadId];
		a[threadId+1] = b[threadId+1] + c[threadId+1];
		a[threadId+2] = b[threadId+2] + c[threadId+2];
		a[threadId+3] = b[threadId+3] + c[threadId+3];
	}
}

int main(){
	int len = 1024;
	int* a1 = (int*)malloc(len * sizeof(int)); 
	int* b1 = (int*)malloc(len * sizeof(int)); 
	int* c1 = (int*)malloc(len * sizeof(int)); 
	for(int i = 0;i<len;i++){
		a1[i] = 1;
		b1[i] = 1;
	}
	int* cudaA;
       	cudaMalloc(&cudaA, sizeof(int) * len);
	int* cudaB;
       	cudaMalloc(&cudaB, sizeof(int) * len);
	int* cudaC;
       	cudaMalloc(&cudaC, sizeof(int) * len);
	cudaMemcpy(cudaA, a1, len*sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(cudaB, b1, len*sizeof(int), cudaMemcpyHostToDevice);
	dim3 grid(4);
	dim3 block(256);
	fun<<<grid, block>>>(cudaA, cudaB, cudaC, len);
	cudaDeviceSynchronize();
	int *result = (int*)malloc(len * sizeof(int));;
	cudaMemcpy(result, cudaC, len * sizeof(int), cudaMemcpyDeviceToHost);
	for(int i = 0;i<len;i++){
		printf(" %d ",result[i]);
	}

	int* cudaA1;
       	cudaMalloc(&cudaA1, sizeof(int) * len);
	int* cudaB1;
       	cudaMalloc(&cudaB1, sizeof(int) * len);
	int* cudaC1;
       	cudaMalloc(&cudaC1, sizeof(int) * len);
	cudaMemcpy(cudaA1, a1, len*sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(cudaB1, b1, len*sizeof(int), cudaMemcpyHostToDevice);
	fun_block_unroll<<<1, block>>>(cudaA1, cudaB1, cudaC1, len);
	cudaDeviceSynchronize();
	cudaMemcpy(result, cudaC, len * sizeof(int), cudaMemcpyDeviceToHost);
	for(int i = 0;i<len;i++){
		printf(" %d ",result[i]);
	}
}
