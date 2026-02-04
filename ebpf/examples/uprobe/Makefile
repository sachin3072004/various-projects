# Makefile
BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
CC ?= cc

CFLAGS := -O2 -g
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LDLIBS := $(shell pkg-config --libs libbpf)

all: hello

hello.bpf.o: hello.bpf.c vmlinux.h
	$(BPF_CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

hello.skel.h: hello.bpf.o
	bpftool gen skeleton $< > $@

hello: hello.c hello.skel.h
	$(CC) $(CFLAGS) hello.c -o $@ $(LIBBPF_CFLAGS) $(LIBBPF_LDLIBS) -lelf -lz

clean:
	rm -f hello.bpf.o hello.skel.h hello

