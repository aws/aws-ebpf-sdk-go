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

// Two GLOBAL programs placed in the SAME section ("tc_cls"). clang emits both
// functions back-to-back into one PROGBITS section, each a global STT_FUNC
// symbol with its own offset and size. The loader must slice each program by
// its own symbol size; loading from a program's start to the end of the whole
// section would make the first program swallow the second.
SEC("tc_cls")
int prog_first(struct __sk_buff *skb)
{
    struct conntrack_key key = {};
    key.src_ip = 0x0a010164;
    struct conntrack_value *val = bpf_map_lookup_elem(&shared_map, &key);
    if (val)
        return BPF_OK;
    return BPF_DROP;
}

SEC("tc_cls")
int prog_second(struct __sk_buff *skb)
{
    struct conntrack_key key = {};
    key.src_ip = 0x0a010165;
    struct conntrack_value *val = bpf_map_lookup_elem(&shared_map, &key);
    if (val)
        return BPF_DROP;
    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
