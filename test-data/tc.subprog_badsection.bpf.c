#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PIN_GLOBAL_NS 2
struct bpf_map_def_pvt { __u32 type; __u32 key_size; __u32 value_size; __u32 max_entries; __u32 map_flags; __u32 pinning; __u32 inner_map_fd; };
struct bpf_map_def_pvt SEC("maps") m = {
    .type = BPF_MAP_TYPE_ARRAY, .key_size = sizeof(__u32), .value_size = sizeof(__u64),
    .max_entries = 1, .pinning = PIN_GLOBAL_NS,
};

// A __noinline subprogram in a CUSTOM section (not .text); the call relocates
// against a symbol outside .text, which the loader does not append.
__attribute__((noinline)) __attribute__((section("mysubprogs")))
int helper_custom(__u32 x) {
    __u32 k = x & 0;
    __u64 *v = bpf_map_lookup_elem(&m, &k);
    if (v && *v > 10) return 2;
    return 1;
}

SEC("tc_cls")
int handle_ingress(struct __sk_buff *skb) {
    if (helper_custom(skb->len)) return BPF_OK;
    return BPF_DROP;
}
char _license[] SEC("license") = "GPL";
