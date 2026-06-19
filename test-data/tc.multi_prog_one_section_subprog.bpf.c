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

struct bpf_map_def_pvt SEC("maps") shared_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct conntrack_key),
    .value_size = sizeof(struct conntrack_value),
    .max_entries = 65536,
    .pinning = PIN_GLOBAL_NS,
};

// A __noinline helper lands in .text as a BPF-to-BPF subprogram.
static __attribute__((noinline)) int lookup(__u32 src_ip)
{
    struct conntrack_key key = {};
    key.src_ip = src_ip;
    struct conntrack_value *val = bpf_map_lookup_elem(&shared_map, &key);
    if (val)
        return val->val[0];
    return 0;
}

// Two GLOBAL programs in the SAME section ("tc_cls") that ALSO call a .text
// subprogram. This is the unsupported layout: BPF-to-BPF call offsets are
// relocated relative to the whole program section, which no longer matches the
// per-program trimmed bytecode the loader builds. The loader must hard-error
// rather than silently emit wrong call offsets.
SEC("tc_cls")
int prog_first(struct __sk_buff *skb)
{
    if (lookup(0x0a010164))
        return BPF_OK;
    return BPF_DROP;
}

SEC("tc_cls")
int prog_second(struct __sk_buff *skb)
{
    if (lookup(0x0a010165))
        return BPF_DROP;
    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
