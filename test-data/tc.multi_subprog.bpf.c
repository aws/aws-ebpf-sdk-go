#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_F_NO_PREALLOC 1
#define PIN_GLOBAL_NS           2

/* 
Note: tc.multi_subprog is an ELF with multiple entry programs that each call a
distinct .text subprogram. The loader does not support that layout (it appends
the whole .text to every program); it is kept only as a fixture to assert the
loader rejects it. See TestMultiSubprogramWithDistinctSubprogsRejected.
*/

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

struct bpf_map_def_pvt SEC("maps") map_alpha = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct conntrack_key),
    .value_size = sizeof(struct conntrack_value),
    .max_entries = 65536,
    .pinning = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt SEC("maps") map_beta = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct conntrack_key),
    .value_size = sizeof(struct conntrack_value),
    .max_entries = 65536,
    .pinning = PIN_GLOBAL_NS,
};

/* Subprogram A: looks up map_alpha. Ends up in .text. */
static __attribute__((noinline)) int lookup_alpha(__u32 src_ip)
{
    struct conntrack_key key = {};
    key.src_ip = src_ip;

    struct conntrack_value *val;
    val = bpf_map_lookup_elem(&map_alpha, &key);
    if (val)
        return val->val[0];
    return 0;
}

/* Subprogram B: looks up map_beta. Ends up in .text. */
static __attribute__((noinline)) int lookup_beta(__u32 src_ip)
{
    struct conntrack_key key = {};
    key.src_ip = src_ip;

    struct conntrack_value *val;
    val = bpf_map_lookup_elem(&map_beta, &key);
    if (val)
        return val->val[0];
    return 0;
}

SEC("tc_cls")
int handle_ingress(struct __sk_buff *skb)
{
    int result = lookup_alpha(0x0a010164);
    if (result)
        return BPF_OK;
    return BPF_DROP;
}

SEC("xdp")
int handle_xdp(struct xdp_md *ctx)
{
    int result = lookup_beta(0x0a010165);
    if (result)
        return XDP_PASS;
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
