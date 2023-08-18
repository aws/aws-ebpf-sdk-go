#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PIN_GLOBAL_NS           2

struct conntrack_key {
   __u32 src_ip;
   __u16 src_port;
   __u32 dest_ip;
   __u16 dest_port;
   __u8  protocol;
};

struct conntrack_value {
   __u8 val[4];
};


struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct bpf_map_def_pvt SEC("maps") aws_conntrack_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size =sizeof(struct conntrack_key),
    .value_size = sizeof(struct conntrack_value),
    .max_entries = 65536,
    .pinning = PIN_GLOBAL_NS,
};

char _license[] SEC("license") = "GPL";