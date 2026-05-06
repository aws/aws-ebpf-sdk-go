#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_F_NO_PREALLOC 1
#define PIN_GLOBAL_NS 2
#define MAX_ENTRIES 65536

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct ipcache_key {
	__u32 ip;
};

struct ipcache_value {
	__u64 timestamp;
};

struct data_t {
	__u32 src_ip;
	__u32 dest_ip;
	__u32 verdict;
};

struct conntrack_key {
	__u32 src_ip;
	__u32 dest_ip;
	__u16 src_port;
	__u16 dest_port;
	__u8 protocol;
};

struct conntrack_value {
	__u8 val;
};

struct lpm_trie_key {
	__u32 prefixlen;
	__u32 ip;
};

struct lpm_trie_val {
	__u32 protocol;
	__u32 start_port;
	__u32 end_port;
};

struct pod_state {
	__u8 state;
};

// Maps that will generate relocations
struct bpf_map_def_pvt SEC("maps") ipcache_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ipcache_key),
	.value_size = sizeof(struct ipcache_value),
	.max_entries = MAX_ENTRIES,
	.map_flags = BPF_F_NO_PREALLOC,
	.pinning = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt SEC("maps") policy_events = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.key_size = 0,
	.value_size = 0,
	.max_entries = 256 * 1024,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt SEC("maps") aws_conntrack_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct conntrack_key),
	.value_size = sizeof(struct conntrack_value),
	.max_entries = MAX_ENTRIES,
	.map_flags = BPF_F_NO_PREALLOC,
	.pinning = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt SEC("maps") egress_map = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct lpm_trie_key),
	.value_size = sizeof(struct lpm_trie_val),
	.max_entries = MAX_ENTRIES,
	.map_flags = BPF_F_NO_PREALLOC,
	.pinning = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt SEC("maps") egress_pod_state_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct pod_state),
	.max_entries = 1,
	.map_flags = BPF_F_NO_PREALLOC,
	.pinning = PIN_GLOBAL_NS,
};

// Function without SEC() - goes to .text section
// This will generate relocations in .rel.text
int checkIPCache(struct data_t *evt, __u32 dest_ip)
{
	struct ipcache_key cache_key = {};
	cache_key.ip = dest_ip;

	// This generates relocation in .text section for ipcache_map
	struct ipcache_value *cache_val = bpf_map_lookup_elem(&ipcache_map, &cache_key);
	if (cache_val != NULL) {
		__u64 current_time = bpf_ktime_get_ns();
		
		if (cache_val->timestamp < current_time) {
			evt->verdict = 0;
			// This generates relocation in .text section for policy_events
			bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
			return BPF_DROP;
		}
		
		evt->verdict = 1;
		bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
		return BPF_OK;
	}

	return BPF_DROP;
}

// Another function without SEC() - also goes to .text section
int evaluateByLookUp(struct lpm_trie_key *trie_key, struct conntrack_key *flow_key, struct pod_state *pst, struct data_t *evt)
{
	// Call the other .text function - generates BPF_CALL to .text
	int ipcache_result = checkIPCache(evt, flow_key->dest_ip);
	if (ipcache_result == BPF_OK) {
		struct conntrack_value new_flow_val = {};
		new_flow_val.val = 1;
		bpf_map_update_elem(&aws_conntrack_map, flow_key, &new_flow_val, 0);
		return BPF_OK;
	}

	struct lpm_trie_val *trie_val = bpf_map_lookup_elem(&egress_map, trie_key);
	if (trie_val == NULL) {
		evt->verdict = 0;
		bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
		return BPF_DROP;
	}

	if (trie_val->protocol == flow_key->protocol) {
		struct conntrack_value new_flow_val = {};
		new_flow_val.val = 1;
		bpf_map_update_elem(&aws_conntrack_map, flow_key, &new_flow_val, 0);
		evt->verdict = 1;
		bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
		return BPF_OK;
	}
	
	evt->verdict = 0;
	bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
	return BPF_DROP;
}

// Main BPF program in tc_cls section
// This will generate relocations in .reltc_cls including calls to .text
SEC("tc_cls")
int handle_egress(struct __sk_buff *skb)
{
	struct lpm_trie_key trie_key = {};
	struct conntrack_key flow_key = {};
	struct conntrack_value *flow_val;
	struct data_t evt = {};
	
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	
	struct ethhdr *ether = data;
	if (data + sizeof(*ether) > data_end) {
		return BPF_OK;
	}

	if (ether->h_proto == 0x08U) {
		data += sizeof(*ether);
		struct iphdr *ip = data;
		
		if (data + sizeof(*ip) > data_end) {
			return BPF_OK;
		}
		
		if (ip->version != 4) {
			return BPF_OK;
		}

		trie_key.prefixlen = 32;
		trie_key.ip = ip->daddr;
		
		flow_key.src_ip = ip->saddr;
		flow_key.dest_ip = ip->daddr;
		flow_key.protocol = ip->protocol;
		
		evt.src_ip = flow_key.src_ip;
		evt.dest_ip = flow_key.dest_ip;

		__u32 key = 0;
		// This generates relocation in .reltc_cls for egress_pod_state_map
		struct pod_state *pst = bpf_map_lookup_elem(&egress_pod_state_map, &key);
		if (pst == NULL) {
			evt.verdict = 0;
			// This generates relocation in .reltc_cls for policy_events
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_DROP;
		}

		// Check if it's an existing flow
		// This generates relocation in .reltc_cls for aws_conntrack_map
		flow_val = bpf_map_lookup_elem(&aws_conntrack_map, &flow_key);
		if (flow_val != NULL) {
			return BPF_OK;
		}

		// Call function in .text section - this generates BPF_CALL relocation to .text
		return evaluateByLookUp(&trie_key, &flow_key, pst, &evt);
	}
	
	return BPF_OK;
}

char _license[] SEC("license") = "GPL";
