#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_F_NO_PREALLOC 1
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

struct conntrack_key {
   __u32 src_ip;
};

struct conntrack_value {
   __u8 val[4];
};

// A GLOBAL (non-namespaced) map referenced ONLY from inside the .text
// subprogram. With the SDK treating it as global, its FD is resolved from the
// sdkCache during .text relocation (the `sdkCache.Get` branch in
// getRelocatedTextSection), exercising the global-map .text relocation path
// that the production NPA agent actually hits (aws_conntrack_map / policy_events
// are global maps used inside subprograms).
struct bpf_map_def_pvt SEC("maps") global_subprog_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct conntrack_key),
    .value_size = sizeof(struct conntrack_value),
    .max_entries = 65536,
    .pinning = PIN_GLOBAL_NS,
};

static __attribute__((noinline)) int lookup_global(__u32 src_ip)
{
    struct conntrack_key key = {};
    key.src_ip = src_ip;
    struct conntrack_value *val = bpf_map_lookup_elem(&global_subprog_map, &key);
    if (val)
        return val->val[0];
    return 0;
}

SEC("tc_cls")
int handle_ingress(struct __sk_buff *skb)
{
    if (lookup_global(0x0a010164))
        return BPF_OK;
    return BPF_DROP;
}

char _license[] SEC("license") = "GPL";
