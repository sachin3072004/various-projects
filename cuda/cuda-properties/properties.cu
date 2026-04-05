#include <stdio.h>
#include <cuda.h>

int main(){
	int deviceCount = 0;
	cudaGetDeviceCount(&deviceCount);
	printf("DeviceCount == %d\n", deviceCount);
	cudaDeviceProp prop;
	int deviceNum = 0;
	cudaGetDeviceProperties(&prop, deviceNum);
	printf("Name %s Multiprocessor %d ClockRate %d TotalGlobalMemory %ul ConstMem %ul \n", 
			prop.name, prop.multiProcessorCount, prop.clockRate, prop.totalGlobalMem , prop.totalConstMem);
}
