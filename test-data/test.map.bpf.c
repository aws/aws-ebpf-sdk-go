#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PIN_GLOBAL_NS           2
#define BPF_MAP_TYPE_RINGBUF 27

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct bpf_map_def_pvt SEC("maps") policy_events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 256 * 1024,
    .pinning = PIN_GLOBAL_NS,
};