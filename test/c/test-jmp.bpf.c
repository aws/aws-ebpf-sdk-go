#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_F_NO_PREALLOC 1
#define ETH_HLEN 14
#define PIN_GLOBAL_NS 2
#define MAX_ENTRIES 1024
#define ETH_P_IP 0x0800

// Use proper BPF helper functions
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct packet_info {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
};

struct rule_entry {
	__u32 action;
	__u32 counter;
};

// Map to store packet filtering rules
struct bpf_map_def_pvt SEC("maps") jmp_test_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct packet_info),
	.value_size = sizeof(struct rule_entry),
	.max_entries = MAX_ENTRIES,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
};

// Map to store statistics
struct bpf_map_def_pvt SEC("maps") stats_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 10,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
};

// Helper function that demonstrates BPF_JMP calls
static __always_inline int validate_packet(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	
	// This will generate BPF_JMP instructions for the conditional checks
	if (data + ETH_HLEN > data_end) {
		return 0; // Invalid packet
	}
	
	struct ethhdr *eth = data;
	
	// BPF_JMP32 instruction for protocol comparison
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return 0; // Not IPv4
	}
	
	return 1; // Valid packet
}

// Helper function that uses BPF helper calls (BPF_CALL instructions)
static __always_inline void update_stats(__u32 stat_type)
{
	__u64 *counter;
	__u64 new_val = 1;
	
	// This bpf_map_lookup_elem call will generate BPF_CALL instruction
	counter = bpf_map_lookup_elem(&stats_map, &stat_type);
	if (counter) {
		// Atomic increment - may generate BPF_JMP for error checking
		__sync_fetch_and_add(counter, 1);
	} else {
		// This bpf_map_update_elem call will generate BPF_CALL instruction
		bpf_map_update_elem(&stats_map, &stat_type, &new_val, BPF_ANY);
	}
}

// Function that demonstrates complex control flow with jumps
static __always_inline int process_tcp_packet(struct iphdr *ip, void *data_end)
{
	struct tcphdr *tcp;
	struct packet_info pkt_info = {};
	struct rule_entry *rule;
	
	tcp = (struct tcphdr *)((char *)ip + sizeof(struct iphdr));
	
	// BPF_JMP instruction for bounds checking
	if ((void *)tcp + sizeof(struct tcphdr) > data_end) {
		return BPF_DROP;
	}
	
	// Fill packet info structure
	pkt_info.src_ip = ip->saddr;
	pkt_info.dst_ip = ip->daddr;
	pkt_info.src_port = bpf_ntohs(tcp->source);
	pkt_info.dst_port = bpf_ntohs(tcp->dest);
	pkt_info.protocol = IPPROTO_TCP;
	
	// BPF_CALL instruction for map lookup
	rule = bpf_map_lookup_elem(&jmp_test_map, &pkt_info);
	
	// BPF_JMP instruction for null check
	if (!rule) {
		update_stats(0); // Default rule counter
		return BPF_OK;
	}
	
	// Update rule counter
	__sync_fetch_and_add(&rule->counter, 1);
	
	// BPF_JMP32 instruction for action comparison
	if (rule->action == 1) {
		update_stats(1); // Accept counter
		return BPF_OK;
	} else if (rule->action == 2) {
		update_stats(2); // Drop counter
		return BPF_DROP;
	}
	
	// Default action
	update_stats(3); // Unknown action counter
	return BPF_OK;
}

// Function that demonstrates UDP packet processing with jumps
static __always_inline int process_udp_packet(struct iphdr *ip, void *data_end)
{
	struct udphdr *udp;
	struct packet_info pkt_info = {};
	struct rule_entry *rule;
	
	udp = (struct udphdr *)((char *)ip + sizeof(struct iphdr));
	
	// BPF_JMP instruction for bounds checking
	if ((void *)udp + sizeof(struct udphdr) > data_end) {
		return BPF_DROP;
	}
	
	// Fill packet info - this demonstrates various BPF_JMP patterns
	pkt_info.src_ip = ip->saddr;
	pkt_info.dst_ip = ip->daddr;
	pkt_info.src_port = bpf_ntohs(udp->source);
	pkt_info.dst_port = bpf_ntohs(udp->dest);
	pkt_info.protocol = IPPROTO_UDP;
	
	// BPF_CALL instruction
	rule = bpf_map_lookup_elem(&jmp_test_map, &pkt_info);
	
	// Complex conditional logic that generates multiple BPF_JMP instructions
	if (rule) {
		// Increment counter
		__sync_fetch_and_add(&rule->counter, 1);
		
		// Nested conditionals generate more BPF_JMP instructions
		if (rule->action == 1) {
			// Special handling for DNS traffic
			if (pkt_info.dst_port == 53 || pkt_info.src_port == 53) {
				update_stats(4); // DNS counter
				return BPF_OK;
			}
			update_stats(1); // Accept counter
			return BPF_OK;
		} else if (rule->action == 2) {
			update_stats(2); // Drop counter
			return BPF_DROP;
		}
	}
	
	// Default handling
	update_stats(0); // Default counter
	return BPF_OK;
}

SEC("tc_cls")
int handle_jmp_test(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth;
	struct iphdr *ip;
	int result;
	
	// Call helper function - this may generate BPF_CALL instruction
	if (!validate_packet(skb)) {
		update_stats(5); // Invalid packet counter
		return BPF_DROP;
	}
	
	eth = data;
	ip = (struct iphdr *)(data + ETH_HLEN);
	
	// BPF_JMP instruction for bounds checking
	if ((void *)ip + sizeof(struct iphdr) > data_end) {
		return BPF_DROP;
	}
	
	// BPF_JMP instruction for version check
	if (ip->version != 4) {
		update_stats(6); // Non-IPv4 counter
		return BPF_DROP;
	}
	
	// Protocol-specific processing with BPF_JMP instructions
	switch (ip->protocol) {
		case IPPROTO_TCP:
			result = process_tcp_packet(ip, data_end);
			break;
		case IPPROTO_UDP:
			result = process_udp_packet(ip, data_end);
			break;
		case IPPROTO_ICMP:
			// Simple ICMP handling with BPF_JMP
			update_stats(7); // ICMP counter
			result = BPF_OK;
			break;
		default:
			// Unknown protocol
			update_stats(8); // Unknown protocol counter
			result = BPF_OK;
			break;
	}
	
	return result;
}

// Kprobe that demonstrates BPF_JMP in different context
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
	__u32 stat_key = 9; // TCP connect counter
	__u64 *counter;
	__u64 new_val = 1;
	
	// BPF_CALL instruction for map lookup
	counter = bpf_map_lookup_elem(&stats_map, &stat_key);
	
	// BPF_JMP instruction for null check
	if (counter) {
		__sync_fetch_and_add(counter, 1);
	} else {
		// BPF_CALL instruction for map update
		bpf_map_update_elem(&stats_map, &stat_key, &new_val, BPF_ANY);
	}
	
	return 0;
}

char _license[] SEC("license") = "GPL";
