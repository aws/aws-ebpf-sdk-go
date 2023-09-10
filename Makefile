.PHONY: all build-linux 

export GOPROXY = direct

CURDIR       := $(abspath .)
TESTDATADIR  := $(CURDIR)/test-data
BPFTOOL      := bpftool
CLANG        := clang
LOGFILE_PATH ?= stdout

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
CLANG_INCLUDE := -I../../..
BPF_CFLAGS := -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -D__TARGET_ARCH_$(ARCH) 
TARGETS := \
		  $(TESTDATADIR)/tc.ingress \
		  $(TESTDATADIR)/tc \
		  $(TESTDATADIR)/test.map \
		  $(TESTDATADIR)/test_license \
		  $(TESTDATADIR)/invalid_map \
		  $(TESTDATADIR)/recoverydata \
		  $(TESTDATADIR)/test-kprobe \
		  $(TESTDATADIR)/xdp \
		  $(TESTDATADIR)/ring_buffer

%.bpf.elf: %.bpf.c
	$(CLANG) $(CLANG_INCLUDE) $(BPF_CFLAGS) -c $< -o $@

## check if the vmlinux exists in /sys/kernel/btf directory
VMLINUX_BTF ?= $(wildcard /sys/kernel/btf/vmlinux)
ifeq ($(VMLINUX_BTF),)
$(error Cannot find a vmlinux)
endif

$(TESTDATADIR)/vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

##@ Run Unit Tests
# Run unit tests
unit-test: $(TESTDATADIR)/vmlinux.h
unit-test: $(addsuffix .bpf.elf,$(TARGETS))
unit-test: export AWS_EBPF_SDK_LOG_FILE=$(LOGFILE_PATH)
unit-test:    ## Run unit tests
	go test -v -coverprofile=coverage.txt -covermode=atomic ./pkg/...

.PHONY: clean
clean:
	-@rm -f $(TESTDATADIR)/vmlinux.h
	-@rm -f $(TESTDATADIR)/*.elf
