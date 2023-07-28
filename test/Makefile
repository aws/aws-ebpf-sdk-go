.PHONY: all build-test build-test-bpf 

export GOPROXY = direct

UNAME_ARCH = $(shell uname -m)
ARCH = $(lastword $(subst :, ,$(filter $(UNAME_ARCH):%,x86_64:x86 aarch64:arm64)))

BUILD_MODE ?= -buildmode=pie
build-test: BUILD_FLAGS = $(BUILD_MODE) -ldflags '-s -w'
build-test:    ## Build the VPC CNI plugin agent using the host's Go toolchain.
	go build $(BUILD_FLAGS) -o main main.go

# Build BPF
CLANG := clang
CLANG_INCLUDE := -I../../..
CFLAGS := -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -march=bpf -D__TARGET_ARCH_$(ARCH)
SRCDIR := c
TARGETS := $(patsubst %.c, %.elf, $(shell find $(SRCDIR) -type f -name "*.c"))

build-test-bpf: ## Build BPF
build-test-bpf: vmlinuxh
build-test-bpf: $(TARGETS)

%.elf: %.c
	$(CLANG) $(CLANG_INCLUDE) $(CFLAGS) -c $< -o $@


vmlinuxh:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(abspath c/vmlinux.h)


##@ Run Tests
# Run tests
run-test: vmlinuxh
run-test: build-test-bpf
run-test: build-test
run-test: export AWS_EBPF_SDK_LOG_FILE=stdout
run-test:    ## Run unit tests
	./main
