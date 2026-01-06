//mpicc hello-world.c -o hello
//mpirun  -np 4 ./hello
#include <mpi.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv) {
    int rank, size;
    char msg[] = "Hello World";
    int tag = 10l;
    MPI_Status status;
    MPI_Init(&argc, &argv);                       // Start MPI [web:39]
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);         // Get this process's rank [web:52]
    if(rank == 0){
	    int sent_result = MPI_Send(msg, strlen(msg) + 1, MPI_CHAR, 1, tag, MPI_COMM_WORLD);
	    printf("Sent_result %d", sent_result);
    }else{
	    char msg1[100] = {'\0'};
	    MPI_Status status;
	    int received_size = 0;
	    int received_result = MPI_Recv(msg1, 11 , MPI_CHAR, 0, tag, MPI_COMM_WORLD, &status);
	    printf("received_result %d Msg1 == %s \n", received_result,msg1);
	    MPI_Get_count(&status, MPI_CHAR,&received_size);
	    printf("Status  SZ -- %d %s \n",  received_size, msg1);

    }
    MPI_Finalize();                               // Clean up MPI [web:52] 
    return 0;
}

