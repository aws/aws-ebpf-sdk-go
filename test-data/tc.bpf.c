#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("tc_cls")
int handle_ingress(struct __sk_buff *skb)
{
	return BPF_OK;
}

SEC("test")
int handle_test_ingress(struct __sk_buff *skb)
{
	return BPF_OK;
}

char _license[] SEC("license") = "GPL";