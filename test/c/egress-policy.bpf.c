#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_F_NO_PREALLOC 1
#define ETH_HLEN 14
#define BPF_MAP_ID_INGRESS_MAP 2
#define MAX_RULES 256
#define MIN_RULES 128
#define PIN_GLOBAL_NS 2
#define RESERVED_IP_PROTOCOL 255
#define ANY_IP_PROTOCOL 254
#define ANY_PORT 0
#define MAX_PORT_PROTOCOL 24
#define CT_VAL_DEFAULT_ALLOW 0
#define CT_VAL_POLICIES_APPLIED 1
#define POLICIES_APPLIED 0
#define DEFAULT_ALLOW 1
#define DEFAULT_DENY 2

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct keystruct
{
  __u32 prefix_len;
  __u8 ip[4];
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

struct conntrack_key {
   __u32 src_ip;
   __u16 src_port;
   __u32 dest_ip;
   __u16 dest_port;
   __u8  protocol;
   __u32 owner_ip;
};

struct conntrack_value {
   __u8 val; // 0 => default-allow, 1 => policies-applied
};

struct data_t {
	__u32  src_ip;
	__u32  src_port;
	__u32  dest_ip;
	__u32  dest_port;
	__u32  protocol;
	__u32  verdict;
	__u32 packet_sz;
	__u8 is_egress;
};

// IPCache structures
struct ipcache_key
{
	__u32 ip;
};

struct ipcache_value
{
	__u64 timestamp; // for cache expiry
	// struct lpm_trie_val ports[MAX_PORT_PROTOCOL]; // port information
};

// IPCache BPF hashmap
struct bpf_map_def_pvt SEC("maps") ipcache_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ipcache_key),
	.value_size = sizeof(struct ipcache_value),
	.max_entries = 65536,
	.map_flags = BPF_F_NO_PREALLOC,
	.pinning = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt SEC("maps") egress_map = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct lpm_trie_key),
	.value_size = sizeof(struct lpm_trie_val[MAX_PORT_PROTOCOL]),
	.max_entries = 65536,
	.map_flags = BPF_F_NO_PREALLOC,
	.pinning = PIN_GLOBAL_NS,
};

struct pod_state {
    __u8 state; // 0 => POLICIES_APPLIED, 1 => DEFAULT_ALLOW, 2 => DEFAULT_DENY
};

struct bpf_map_def_pvt SEC("maps") egress_pod_state_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32), // default key = 0. We are storing a single state per pod identifier
    .value_size  = sizeof(struct pod_state),
    .max_entries = 1,
	.map_flags = BPF_F_NO_PREALLOC,
    .pinning     = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt SEC("maps") aws_conntrack_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct conntrack_key),
	.value_size = sizeof(struct conntrack_value),
	.max_entries = 65536,
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

// IPCache lookup function
static inline int checkIPCache(struct data_t *evt, __u32 dest_ip)
{
	struct ipcache_key cache_key = {};
	cache_key.ip = dest_ip;
	bpf_printk("Dest IP %u", dest_ip);
	bpf_printk("current boot time %llu", bpf_ktime_get_ns());

	struct ipcache_value *cache_val = bpf_map_lookup_elem(&ipcache_map, &cache_key);
	if (cache_val != NULL)
	{
		bpf_printk("cache hit occured");
		// Get current timestamp (nanoseconds since boot)
		__u64 current_time = bpf_ktime_get_ns();
		bpf_printk("current time %llu, expiry time %llu", current_time, cache_val->timestamp);
		
		// Check if cached entry has expired
		if (cache_val->timestamp < current_time)
		{
			bpf_printk("cache entry expired");
			// Entry has expired, remove it from cache and deny
			// bpf_map_delete_elem(&ipcache_map, &cache_key);
			evt->verdict = 0;
			bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
			return BPF_DROP;
		}
		bpf_printk("cache entry valid");
		// IP found in cache and not expired, allow
		evt->verdict = 1;
		bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
		return BPF_OK;
	}

	// IP not found in cache or not allowed
	return BPF_DROP;
}

static __always_inline int evaluateByLookUp(struct keystruct trie_key, struct conntrack_key flow_key, struct pod_state *pst, struct data_t evt) {	

	int ipcache_result = checkIPCache(&evt, flow_key.dest_ip);
	if (ipcache_result == BPF_OK)
	{
		// IP found in cache and allowed, inject into conntrack and allow
		struct conntrack_value new_flow_val = {};
		if (pst->state == DEFAULT_ALLOW)
		{
			new_flow_val.val = CT_VAL_DEFAULT_ALLOW;
		}
		else
		{
			new_flow_val.val = CT_VAL_POLICIES_APPLIED;
		}
		bpf_map_update_elem(&aws_conntrack_map, &flow_key, &new_flow_val, 0);
		return BPF_OK;
	}

	//Check if it's in the allowed list
	struct lpm_trie_val *trie_val = bpf_map_lookup_elem(&egress_map, &trie_key);
	if (trie_val == NULL) {
		evt.verdict = 0;
		bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
		return BPF_DROP;
	}

	for (int i = 0; i < MAX_PORT_PROTOCOL; i++, trie_val++){
		if (trie_val->protocol == RESERVED_IP_PROTOCOL) {
			evt.verdict = 0;
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_DROP;
		}
		
		// 1. ANY_IP_PROTOCOL:
		//    - If the rule specifies ANY_IP_PROTOCOL (i.e., applies to all L4 protocols),
		//    - Then match if:
		//        - start_port is ANY_PORT → rule applies to all ports
		//        - OR l4_dst_port is exactly the start_port
		//        - OR l4_dst_port falls within (start_port, end_port] range
		//
		// 2. Specific Protocol Match:
		//    - If trie_val->protocol matches the packet's IP protocol (e.g., TCP or UDP),
		//    - Then apply the same port match logic as above.

		if ((trie_val->protocol == ANY_IP_PROTOCOL && 
			((trie_val->start_port == ANY_PORT) || (flow_key.dest_port == trie_val->start_port) ||
			(flow_key.dest_port > trie_val->start_port && flow_key.dest_port <= trie_val->end_port))) || 
			(trie_val->protocol == flow_key.protocol &&
			((trie_val->start_port == ANY_PORT) || (flow_key.dest_port == trie_val->start_port) ||
			(flow_key.dest_port > trie_val->start_port && flow_key.dest_port <= trie_val->end_port)))) {
			//Inject in to conntrack map
			struct conntrack_value new_flow_val = {};
			if (pst->state == DEFAULT_ALLOW) {
				new_flow_val.val = CT_VAL_DEFAULT_ALLOW;
			} else {
				new_flow_val.val = CT_VAL_POLICIES_APPLIED;
			}
			bpf_map_update_elem(&aws_conntrack_map, &flow_key, &new_flow_val, 0); // 0 - BPF_ANY
			evt.verdict = 1;
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_OK;
		}
	}
	evt.verdict = 0;
	bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
	return BPF_DROP;
}

SEC("tc_cls")
int handle_egress(struct __sk_buff *skb)
{
	bpf_printk("entered handle_egress fn\n");
	struct keystruct trie_key;
	__u32 l4_src_port = 0;
	__u32 l4_dst_port = 0;
	struct conntrack_key flow_key;
	struct conntrack_value *flow_val;
	struct conntrack_key reverse_flow_key;
	struct conntrack_value *reverse_flow_val;
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	__u8 src_ip[4];

	__builtin_memset(&flow_key, 0, sizeof(flow_key));
	__builtin_memset(&src_ip, 0, sizeof(src_ip));
	__builtin_memset(&reverse_flow_key, 0, sizeof(reverse_flow_key));


	struct ethhdr *ether = data;
	if (data + sizeof(*ether) > data_end) {
		return BPF_OK;
	}

	if (ether->h_proto == 0x08U) {  // htons(ETH_P_IP) -> 0x08U
		data += sizeof(*ether);
		struct iphdr *ip = data;
		struct tcphdr *l4_tcp_hdr = data + sizeof(struct iphdr);
		struct udphdr *l4_udp_hdr = data + sizeof(struct iphdr);
		struct sctphdr *l4_sctp_hdr = data + sizeof(struct iphdr);

		if (data + sizeof(*ip) > data_end) {
			return BPF_OK;
		}
		if (ip->version != 4) {
			return BPF_OK;
		}

		switch (ip->protocol) {
			case IPPROTO_TCP:
				if (data + sizeof(*ip) + sizeof(*l4_tcp_hdr) > data_end) {
					return BPF_OK;
				}
				l4_src_port = (((((unsigned short)(l4_tcp_hdr->source) & 0xFF)) << 8) | (((unsigned short)(l4_tcp_hdr->source) & 0xFF00) >> 8));
				l4_dst_port = (((((unsigned short)(l4_tcp_hdr->dest) & 0xFF)) << 8) | (((unsigned short)(l4_tcp_hdr->dest) & 0xFF00) >> 8));
				break;
			case IPPROTO_UDP:
				if (data + sizeof(*ip) + sizeof(*l4_udp_hdr) > data_end) {
					return BPF_OK;
				}
				l4_src_port = (((((unsigned short)(l4_udp_hdr->source) & 0xFF)) << 8) | (((unsigned short)(l4_udp_hdr->source) & 0xFF00) >> 8));
				l4_dst_port = (((((unsigned short)(l4_udp_hdr->dest) & 0xFF)) << 8) | (((unsigned short)(l4_udp_hdr->dest) & 0xFF00) >> 8));
				break;
			case IPPROTO_SCTP:
				if (data + sizeof(*ip) + sizeof(*l4_sctp_hdr) > data_end) {
					return BPF_OK;
				}
				l4_src_port = (((((unsigned short)(l4_sctp_hdr->source) & 0xFF)) << 8) | (((unsigned short)(l4_sctp_hdr->source) & 0xFF00) >> 8));
				l4_dst_port = (((((unsigned short)(l4_sctp_hdr->dest) & 0xFF)) << 8) | (((unsigned short)(l4_sctp_hdr->dest) & 0xFF00) >> 8));
				break;
		}

		trie_key.prefix_len = 32;
		trie_key.ip[0] = ip->daddr & 0xff;
		trie_key.ip[1] = (ip->daddr >> 8) & 0xff;
		trie_key.ip[2] = (ip->daddr >> 16) & 0xff;
		trie_key.ip[3] = (ip->daddr >> 24) & 0xff;

		src_ip[0] = ip->saddr & 0xff;
		src_ip[1] = (ip->saddr >> 8) & 0xff;
		src_ip[2] = (ip->saddr >> 16) & 0xff;
		src_ip[3] = (ip->saddr >> 24) & 0xff;

		// Check for an existing flow in the conntrack table
		flow_key.src_ip = ip->saddr;
		flow_key.src_port = l4_src_port;
		flow_key.dest_ip = ip->daddr;
		flow_key.dest_port = l4_dst_port;
		flow_key.protocol = ip->protocol;
		flow_key.owner_ip = ip->saddr;

		struct data_t evt = {};
		evt.src_ip = flow_key.src_ip;
		evt.src_port = flow_key.src_port;
		evt.dest_ip = flow_key.dest_ip;
		evt.dest_port = flow_key.dest_port;
		evt.protocol = flow_key.protocol;
		evt.is_egress = 1;
		evt.packet_sz = skb->len; 
		__u32 key = 0; 
		struct pod_state *pst = bpf_map_lookup_elem(&egress_pod_state_map, &key);
		// There should always be an entry in pod_state_map. pst returned in above line should never be null.
		if (pst == NULL) {
			evt.verdict = 0;
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_DROP;
		}

		if (pst->state == DEFAULT_DENY) {
			evt.verdict = 0;
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_DROP;
		}

		//Check if it's an existing flow
		flow_val = bpf_map_lookup_elem(&aws_conntrack_map, &flow_key);

		if (flow_val != NULL) {
			// If it's a "default allow" flow, check if pod has flipped to "policies applied" state
			if (flow_val->val == CT_VAL_DEFAULT_ALLOW && pst->state == DEFAULT_ALLOW) {
				return BPF_OK;
			}
			if (flow_val->val == CT_VAL_POLICIES_APPLIED && pst->state == POLICIES_APPLIED) {
				return BPF_OK;
			}
			if (flow_val->val == CT_VAL_POLICIES_APPLIED && pst->state == DEFAULT_ALLOW) {
				flow_val->val = CT_VAL_DEFAULT_ALLOW;
				bpf_map_update_elem(&aws_conntrack_map, &flow_key, flow_val, 0); // 0 -> BPF_ANY
				return BPF_OK;
			}
			if (flow_val->val == CT_VAL_DEFAULT_ALLOW && pst->state == POLICIES_APPLIED) {
				int ret = evaluateByLookUp(trie_key, flow_key, pst, evt);
				if (ret == BPF_DROP) {
					bpf_map_delete_elem(&aws_conntrack_map, &flow_key);
					return BPF_DROP;
				} 
				return BPF_OK;
			}
		}

		//Check for the reverse flow entry in the conntrack table
		reverse_flow_key.src_ip = ip->daddr;
		reverse_flow_key.src_port = l4_dst_port;
		reverse_flow_key.dest_ip = ip->saddr;
		reverse_flow_key.dest_port = l4_src_port;
		reverse_flow_key.protocol = ip->protocol;
		reverse_flow_key.owner_ip = ip->saddr;

		//Check if it's a response packet
		reverse_flow_val = bpf_map_lookup_elem(&aws_conntrack_map, &reverse_flow_key);

		if (reverse_flow_val != NULL) { 
			return BPF_OK;
		}

		if (pst->state == DEFAULT_ALLOW) {
			struct conntrack_value new_flow_val = {};
			new_flow_val.val = CT_VAL_DEFAULT_ALLOW;
			bpf_map_update_elem(&aws_conntrack_map, &flow_key, &new_flow_val, 0); // 0 - BPF_ANY
			evt.verdict = 1;
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_OK;
		}

		return evaluateByLookUp(trie_key, flow_key, pst, evt);
		
	}
	return BPF_OK;
}
char _license[] SEC("license") = "GPL";
