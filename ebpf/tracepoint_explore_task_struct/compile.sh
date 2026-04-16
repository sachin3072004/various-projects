clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c memory_snapshot.bpf.c -o memory_snapshot.bpf.o
llvm-strip -g memory_snapshot.bpf.o 
bpftool gen skeleton memory_snapshot.bpf.o > memory_snapshot.skel.h
cc -O2 -g memory_snapshot.c -o memory_snapshot -lbpf -lelf -lz
