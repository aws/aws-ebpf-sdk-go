// SPDX-License-Identifier: GPL-2.0
// Test program for R_BPF_64_32 relocation handling with function inlining
// This program tests proper BPF function inlining and relocation processing

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PIN_NONE 0

// TC action constants
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3

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
struct bpf_map_def_pvt SEC("maps") counter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 10,
	.map_flags = 0,
	.pinning = PIN_NONE,
};

// Helper function that will be placed in .text section
// Using static __always_inline to ensure proper inlining for BPF
static __always_inline int increment_counter(__u32 key) {
    __u64 *value;
    __u64 initial_value = 1;
    
    value = bpf_map_lookup_elem(&counter_map, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
        return *value;
    }
    
    // Initialize counter if it doesn't exist
    bpf_map_update_elem(&counter_map, &key, &initial_value, BPF_NOEXIST);
    return 1;
}

// Another helper function for packet validation
static __always_inline int validate_packet_size(__u32 size) {
    // Packet size validation logic
    if (size < 64) {
        return -1;  // Too small
    }
    if (size > 1500) {
        return -2;  // Too large
    }
    return 0;  // Valid size
}

// Third helper function for hash calculation
static __always_inline __u32 calculate_hash(__u32 data) {
    // Simple hash function
    __u32 hash = data;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;
    return hash;
}

// Main TC classifier program - this will be in tc_cls section
// The calls to the helper functions should create R_BPF_64_32 relocations
SEC("tc_cls")
int packet_processor(struct __sk_buff *skb) {
    __u32 packet_size = skb->len;
    __u32 key = 0;
    int validation_result;
    int counter_value;
    __u32 hash_value;
    
    // First cross-section call - validate packet size
    validation_result = validate_packet_size(packet_size);
    if (validation_result < 0) {
        return TC_ACT_SHOT;  // Drop invalid packets
    }
    
    // Second cross-section call - increment counter
    counter_value = increment_counter(key);
    if (counter_value < 0) {
        return TC_ACT_SHOT;  // Error in counter update
    }
    
    // Third cross-section call - calculate hash
    hash_value = calculate_hash(packet_size);
    
    // Use hash value to determine action (just for testing)
    if (hash_value % 100 == 0) {
        return TC_ACT_PIPE;  // Pass to next stage
    }
    
    return TC_ACT_OK;  // Allow packet
}
