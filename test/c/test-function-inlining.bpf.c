// SPDX-License-Identifier: GPL-2.0
// Test program for R_BPF_64_32 relocation and function inlining
// This program has a function in .text section called from tc_cls section

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PIN_NONE 0

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

char _license[] SEC("license") = "GPL";

// Map for testing
struct bpf_map_def_pvt SEC("maps") test_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
	.map_flags = 0,
	.pinning = PIN_NONE,
};

// Helper function in .text section - explicitly prevent inlining
// This will NOT be inlined and will generate cross-section relocations
__attribute__((noinline)) int helper_function(__u32 key) {
    __u64 *value;
    __u64 counter = 1;
    
    value = bpf_map_lookup_elem(&test_map, &key);
    if (value) {
        *value += counter;
        return 0;
    }
    
    // If key doesn't exist, try to update it
    bpf_map_update_elem(&test_map, &key, &counter, BPF_ANY);
    return 1;
}

// Another helper function to test multiple cross-section calls
__attribute__((noinline)) int validation_function(__u32 data) {
    // Simple validation logic
    if (data > 1000) {
        return -1;  // Invalid
    }
    return data * 2;  // Valid, return doubled value
}

// Main TC classifier program in tc_cls section (GLOBAL binding)
// This will call the helper functions, creating R_BPF_64_32 relocations
SEC("tc_cls")
int test_classifier(struct __sk_buff *skb) {
    __u32 key = 0;
    __u32 data_len = skb->len;
    int result;
    
    // First cross-section function call - should create R_BPF_64_32 relocation
    result = helper_function(key);
    if (result < 0) {
        return TC_ACT_SHOT;  // Drop packet
    }
    
    // Second cross-section function call - test multiple relocations
    int validated = validation_function(data_len);
    if (validated < 0) {
        return TC_ACT_SHOT;  // Drop invalid packet
    }
    
    // Allow packet to pass
    return TC_ACT_OK;
}
