#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("tc_cls")
int tailcall_target_drop(struct __sk_buff *skb)
{
	return BPF_DROP;
}

SEC("tc_cls")
int tailcall_target_pass(struct __sk_buff *skb)
{
	return BPF_OK;
}

char _license[] SEC("license") = "GPL";
