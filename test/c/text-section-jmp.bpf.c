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

struct test_key {
	__u32 id;
};

struct test_value {
	__u64 counter;
	__u32 flags;
};

// Map with proper section annotation
struct bpf_map_def_pvt SEC("maps") text_test_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct test_key),
	.value_size = sizeof(struct test_value),
	.max_entries = MAX_ENTRIES,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
};

// Function without SEC() annotation - should go to .text section
int text_section_function(void *ctx)
{
	struct test_key key = {.id = 1};
	struct test_value *value;
	struct test_value new_value = {.counter = 1, .flags = 0};
	
	// This map lookup should generate relocations in .text section
	value = bpf_map_lookup_elem(&text_test_map, &key);
	
	// BPF_JMP instruction for null check
	if (value) {
		// Increment counter - generates more JMP instructions
		if (value->counter < 1000) {
			__sync_fetch_and_add(&value->counter, 1);
			
			// Nested conditional - more JMP instructions
			if (value->counter % 10 == 0) {
				value->flags = 1;
			} else {
				value->flags = 0;
			}
		}
		return 1; // Success
	} else {
		// Map update - should generate BPF_CALL with relocation
		int ret = bpf_map_update_elem(&text_test_map, &key, &new_value, 0);
		
		// BPF_JMP for return value check
		if (ret == 0) {
			return 1; // Success
		} else {
			return 0; // Failure
		}
	}
}

// Another function without SEC() - should also go to .text
int another_text_function(int input)
{
	struct test_key key = {.id = input};
	struct test_value *value;
	
	// More map operations in .text section
	value = bpf_map_lookup_elem(&text_test_map, &key);
	
	// Complex control flow with multiple JMP instructions
	if (value) {
		if (value->counter > 100) {
			if (value->flags == 1) {
				return 3; // High priority
			} else {
				return 2; // Medium priority
			}
		} else {
			return 1; // Low priority
		}
	}
	
	return 0; // Not found
}

// Helper function that calls other functions - generates BPF_CALL instructions
int helper_with_calls(void *ctx, int param)
{
	int result1, result2;
	
	// Function calls that should generate BPF_CALL instructions
	result1 = text_section_function(ctx);
	result2 = another_text_function(param);
	
	// Conditional logic based on results
	if (result1 > 0 && result2 > 0) {
		return result1 + result2;
	} else if (result1 > 0) {
		return result1;
	} else if (result2 > 0) {
		return result2;
	} else {
		return -1; // Error
	}
}

char _license[] SEC("license") = "GPL";

// Add a proper BPF program entry point
SEC("tc_cls")
int text_section_main(struct __sk_buff *skb)
{
	// Call our text section functions to generate JMP relocations
	int result = helper_with_calls(skb, 42);
	
	// Simple conditional logic
	if (result > 0) {
		return BPF_OK;
	} else {
		return BPF_DROP;
	}
}
