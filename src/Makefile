CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
LIBBPF_INCLUDES := /usr/include/bpf

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I. -I$(LIBBPF_INCLUDES)

all: command-logger.bpf.o

command-logger.bpf.o: command-logger.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c command-logger.bpf.c -o command-logger.bpf.o

clean:
	rm -f *.o
