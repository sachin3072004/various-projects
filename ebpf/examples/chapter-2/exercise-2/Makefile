# Makefile
BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
CC ?= cc

CFLAGS := -O2 -g
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LDLIBS := $(shell pkg-config --libs libbpf)

all: exercise-2

syscall.bpf.o: syscall.bpf.c vmlinux.h
	$(BPF_CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

exercise-2: exercise-2.c syscall.bpf.o
	$(CC) $(CFLAGS) exercise-2.c -o $@ $(LIBBPF_CFLAGS) $(LIBBPF_LDLIBS) -lelf -lz -pthread

clean:
	rm -f *.bpf.o *.skel.h exercise-2

