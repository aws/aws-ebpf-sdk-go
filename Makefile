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

# ALLPKGS is the set of packages provided in source.
ALLPKGS = $(shell go list ./...)

# Check formatting of source code files without modification.
check-format: FORMAT_FLAGS = -l
check-format: format

# Run go vet on source code.
vet:    ## Run go vet on source code.
	go vet $(ALLPKGS)

# Build BPF
CLANG := clang
CLANG_INCLUDE := -I../../..
BPF_CFLAGS := -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -D__TARGET_ARCH_$(ARCH) 
TARGETS := \
		  test-data/tc.ingress \
		  test-data/tc \
		  test-data/test.map \
		  test-data/test_license \
		  test-data/invalid_map \
		  test-data/recoverydata \
		  test-data/test-kprobe \
		  test-data/xdp \
		  test-data/ring_buffer

%.bpf.elf: %.bpf.c
	$(CLANG) $(CLANG_INCLUDE) $(BPF_CFLAGS) -c $< -o $@

vmlinuxh:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(abspath ./test-data/vmlinux.h)

##@ Run Unit Tests
# Run unit tests
unit-test: vmlinuxh
unit-test: $(addsuffix .bpf.elf,$(TARGETS))
unit-test: export AWS_EBPF_SDK_LOG_FILE=stdout
unit-test:    ## Run unit tests
	go test -v -coverprofile=coverage.txt -covermode=atomic ./pkg/...

.PHONY: clean
clean:
	-@rm -f test-data/*.elf
