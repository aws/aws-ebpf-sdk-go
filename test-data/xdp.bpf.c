#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("xdp")
int  xdp_test_prog(struct xdp_md *ctx)
{
	return XDP_DROP;
}
char _license[] SEC("license") = "GPL";