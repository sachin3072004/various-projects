//nvcc -arch=sm_75 -rdc=true -lcudadevrt -o dynamic dynamic_parallism.cu
#include <stdio.h>
#include <cuda.h>


__global__ void child(){
	printf("Child\n");
}

__global__ void parent(){
	printf("Parent\n");
	child<<<2,2>>>();
}

int main(){
	dim3 grid(1);
	dim3 block(1);
	parent<<<grid,block>>>();
	cudaDeviceSynchronize();
}
