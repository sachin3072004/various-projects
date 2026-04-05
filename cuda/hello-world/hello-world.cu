#include <stdio.h>
#include <cuda.h>
#include <unistd.h>
#include <stdlib.h>

__global__ void dkernel(){
		printf("Hello World11 %d\n", threadIdx.x);
}

__global__ void dkernel2(){
	printf("Hello World22 %d\n", threadIdx.x);
}

int main(){
	dim3 grid(8,1,1);
	dim3 block(4,2,1);
	dkernel<<<grid, block>>>();
	cudaDeviceSynchronize();
}
