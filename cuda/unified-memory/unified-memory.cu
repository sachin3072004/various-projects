#include <cuda.h>
#include <cuda_runtime.h>
#include <stdio.h>

__global__ void add(int*x, int*y,int*z){
	int index = blockIdx.x * blockDim.x + threadIdx.x;
	z[index] = x[index] + y[index];
}
int main(){
	int *x;
	int *y;
	int *z;
	int N = 1024;
	cudaMallocManaged(&x,  N* sizeof(int));
	cudaMallocManaged(&y,  N* sizeof(int));
	cudaMallocManaged(&z,  N* sizeof(int));
	for(int i = 0;i<1024;i++){
		x[i] = i;
		y[i] = i;
	}
	int numBlock = 4;
	int blockSz = 256;
	add<<<numBlock,blockSz>>>(x,y,z);
	cudaDeviceSynchronize();
	for(int i = 0;i<1024;i++){
		printf("Z %d X %d Y %d\n", z[i],x[i],y[i]);
	}


}
