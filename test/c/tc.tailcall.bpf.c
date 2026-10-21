#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_MAP_TYPE_PROG_ARRAY 3
#define PIN_GLOBAL_NS           2

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct bpf_map_def_pvt SEC("maps") tailcall_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 4,
	.pinning = PIN_GLOBAL_NS,
};

SEC("tc_cls")
int handle_ingress(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &tailcall_map, 0);
	return BPF_OK;
}

SEC("tc_cls")
int handle_egress(struct __sk_buff *skb)
{
	bpf_tail_call(skb, &tailcall_map, 1);
	return BPF_DROP;
}

char _license[] SEC("license") = "GPL";
