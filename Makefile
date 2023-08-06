.PHONY: all build-linux 

export GOPROXY = direct

UNAME_ARCH = $(shell uname -m)
ARCH = $(lastword $(subst :, ,$(filter $(UNAME_ARCH):%,x86_64:x86 aarch64:arm64)))


BUILD_MODE ?= -buildmode=pie
build-linux: BUILD_FLAGS = $(BUILD_MODE) -ldflags '-s -w'
build-linux:    ## Build all packages in /pkg.
	find ./pkg -type d -exec sh -c 'echo "Compiling package in: {}" && cd {} && go build' \;

format:       ## Format all Go source code files.
	@command -v goimports >/dev/null || { echo "ERROR: goimports not installed"; exit 1; }
	@exit $(shell find ./* \
	  -type f \
	  -name '*.go' \
	  -print0 | sort -z | xargs -0 -- goimports $(or $(FORMAT_FLAGS),-w) | wc -l | bc)

# Build BPF
CLANG := clang
CLANG_INCLUDE := -I../../..
EBPF_SOURCE := test-data/tc.ingress.bpf.c
EBPF_BINARY := test-data/tc.ingress.bpf.elf
EBPF_TEST_SOURCE := test-data/tc.bpf.c
EBPF_TEST_BINARY := test-data/tc.bpf.elf 
EBPF_TEST_MAP_SOURCE := test-data/test.map.bpf.c
EBPF_TEST_MAP_BINARY := test-data/test.map.bpf.elf
EBPF_TEST_LIC_SOURCE := test-data/test_license.bpf.c
EBPF_TEST_LIC_BINARY := test-data/test_license.bpf.elf
EBPF_TEST_INV_MAP_SOURCE := test-data/invalid_map.bpf.c
EBPF_TEST_INV_MAP_BINARY := test-data/invalid_map.bpf.elf   
build-bpf: ## Build BPF
	$(CLANG) $(CLANG_INCLUDE) -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -march=bpf -D__TARGET_ARCH_$(ARCH) -c $(EBPF_SOURCE) -o $(EBPF_BINARY)
	$(CLANG) $(CLANG_INCLUDE) -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -march=bpf -D__TARGET_ARCH_$(ARCH) -c $(EBPF_TEST_SOURCE) -o $(EBPF_TEST_BINARY)
	$(CLANG) $(CLANG_INCLUDE) -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -march=bpf -D__TARGET_ARCH_$(ARCH) -c $(EBPF_TEST_MAP_SOURCE) -o $(EBPF_TEST_MAP_BINARY)
	$(CLANG) $(CLANG_INCLUDE) -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -march=bpf -D__TARGET_ARCH_$(ARCH) -c $(EBPF_TEST_LIC_SOURCE) -o $(EBPF_TEST_LIC_BINARY)
	$(CLANG) $(CLANG_INCLUDE) -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -march=bpf -D__TARGET_ARCH_$(ARCH) -c $(EBPF_TEST_INV_MAP_SOURCE) -o $(EBPF_TEST_INV_MAP_BINARY)

vmlinuxh:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(abspath ./test-data/vmlinux.h)

##@ Run Unit Tests
# Run unit tests
unit-test: vmlinuxh
unit-test: build-bpf
unit-test: export AWS_EBPF_SDK_LOG_FILE=stdout
unit-test:    ## Run unit tests
	go test -v -coverprofile=coverage.txt -covermode=atomic ./pkg/...
