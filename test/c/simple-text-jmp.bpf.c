#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_F_NO_PREALLOC 1
#define PIN_GLOBAL_NS 2
#define MAX_ENTRIES 1024

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct simple_key {
	__u32 id;
};

struct simple_value {
	__u64 counter;
};

// Map that will generate relocations in .text section
struct bpf_map_def_pvt SEC("maps") simple_text_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct simple_key),
	.value_size = sizeof(struct simple_value),
	.max_entries = MAX_ENTRIES,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
};

// Simple helper function without SEC() - goes to .text section
static __always_inline int simple_text_helper(int input)
{
	struct simple_key key = {.id = input};
	struct simple_value *value;
	
	// This map lookup generates relocation in .text section
	value = bpf_map_lookup_elem(&simple_text_map, &key);
	
	// Simple conditional - generates BPF_JMP instruction
	if (value) {
		return (int)value->counter;
	}
	
	return 0;
}

// Main BPF program that calls the text section function
SEC("tc_cls")
int simple_text_main(struct __sk_buff *skb)
{
	int result;
	
	// Call function in .text section - this should generate BPF_CALL to .text
	result = simple_text_helper(1);
	
	// Simple conditional logic with BPF_JMP
	if (result > 0) {
		return BPF_OK;
	} else {
		// Try to update the map
		struct simple_key key = {.id = 1};
		struct simple_value new_val = {.counter = 1};
		
		int ret = bpf_map_update_elem(&simple_text_map, &key, &new_val, BPF_ANY);
		if (ret == 0) {
			return BPF_OK;
		}
	}
	
	return BPF_DROP;
}

char _license[] SEC("license") = "GPL";
