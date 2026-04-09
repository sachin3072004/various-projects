#include <stdio.h>
#include <cuda.h>


__global__ void sum(int* array, int sz, int* cudaResult){
	int jump = 1;
	int threadId = blockDim.x * blockIdx.x + threadIdx.x;
	int index1 =   2 * (threadId);
	int index2 = index1 + jump;
	while(index2 < sz){
		printf("ThreadIdx.x %d Index1 %d index2 %d \n", threadId, index1, index2);
		if(index2 < sz){
			array[index1] += array[index2];
			printf("index1 %d array[index1] %d \n",index1, array[index1]);
		}
		jump = jump * 2;
		index1 = 2 * index1;
		index2 = index1 + jump;
		__syncthreads();
	}
	*cudaResult = array[0];
}

int main(){
	int len = 1024;
	dim3 grid(1);
	dim3 block(1024);
	int  array[len];
       	for(int i = 0; i<len; i++){
		array[i] = 1;
	}
	int* cudaArray;
       	cudaMalloc(&cudaArray, len*sizeof(int));
	int cudaResult = 0;
	cudaMemcpy(cudaArray, array,len*sizeof(int), cudaMemcpyHostToDevice);
	sum<<<grid,block>>>(cudaArray, len, &cudaResult);
	int result = 0;
	cudaMemcpy(&result, &cudaResult, sizeof(int), cudaMemcpyDeviceToHost);
	cudaDeviceSynchronize();
	printf("Result == %d", result);

}
