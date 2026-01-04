//mpicc hello-world.c -o hello
//mpirun --oversubscribe -np 4 ./hello
#include <mpi.h>
#include <stdio.h>

int main(int argc, char** argv) {
    int rank, size;

    MPI_Init(&argc, &argv);                       // Start MPI [web:39]
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);         // Get this process's rank [web:52]
    MPI_Comm_size(MPI_COMM_WORLD, &size);         // Get total number of processes [web:39]

    printf("Hello from rank %d of %d\n", rank, size);  // Print message [web:39]

    MPI_Finalize();                               // Clean up MPI [web:52]
    return 0;
}

