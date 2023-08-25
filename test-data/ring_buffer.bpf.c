#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_MAP_TYPE_RINGBUF 27
#define PIN_GLOBAL_NS 2

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct bpf_map_def_pvt SEC("maps") test_events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 256 * 1024,
    .pinning = PIN_GLOBAL_NS,
};

SEC("kprobe/__nf_conntrack_hash_insert")
int conn_insert(struct pt_regs *ctx) {
	__u32 evt_test = 20;
	bpf_ringbuf_output(&test_events, &evt_test, sizeof(evt_test), 2);
	return 0;
}

char _license[] SEC("license") = "GPL";