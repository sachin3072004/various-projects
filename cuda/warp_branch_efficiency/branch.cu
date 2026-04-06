#include <stdio.h>
#include <cuda.h>

__device__ void mul(int a,int b, int *result){
	*result = a * b;
}

__device__ void add(int a,int b,int *result){
	*result = a + b;
}
__global__ void fun(){
	int id = threadIdx.x;
	int a = 10;
	int b = 20;
	int result = 0;
	if(id %2 == 0){
		mul(a,b,&result);
	}else{
		add(a,b,&result);
	}
	printf("REsult %d\n", result);
}
int main(){
	dim3 block(1024);	
	dim3 grid(100);
	fun<<<grid,block>>>();
	cudaDeviceSynchronize();

}

