# Makefile
BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
CC ?= cc

CFLAGS := -O2 -g
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LDLIBS := $(shell pkg-config --libs libbpf)

all: exercise-1

exercise-1.bpf.o: exercise-1.bpf.c vmlinux.h
	$(BPF_CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

exercise-1: exercise-1.c exercise-1.bpf.o
	$(CC) $(CFLAGS) exercise-1.c -o $@ $(LIBBPF_CFLAGS) $(LIBBPF_LDLIBS) -lelf -lz -pthread

clean:
	rm -f *.bpf.o *.skel.h exercise-1

