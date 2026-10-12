#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define BPF_F_NO_PREALLOC 1
#define PIN_GLOBAL_NS     2      // pin the map under the SDK's global namespace
#define ETH_P_IP          0x0800 // EtherType for IPv4

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct bpf_map_def_pvt SEC("maps") kfunc_counters = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 2,
	.pinning = PIN_GLOBAL_NS,
};

// 12-byte bpf_ct_opts layout, accepted by every kernel with the kfuncs.
struct bpf_ct_opts___local {
	s32 netns_id;
	s32 error;
	u8 l4proto;
	u8 dir;
	u8 reserved[2];
};

extern struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *skb, struct bpf_sock_tuple *t,
					 u32 tuple__sz, struct bpf_ct_opts___local *opts,
					 u32 opts__sz) __ksym;
extern int bpf_ct_change_timeout(struct nf_conn *nfct, u32 timeout) __ksym;
extern void bpf_ct_release(struct nf_conn *nfct) __ksym;

static __always_inline void count(__u32 idx)
{
	__u64 *val = bpf_map_lookup_elem(&kfunc_counters, &idx);
	if (val)
		__sync_fetch_and_add(val, 1);
}

// Inlined, so its kfunc calls end up in the program section.
static __always_inline int shorten(struct __sk_buff *skb, __u32 saddr, __u32 daddr)
{
	struct bpf_sock_tuple tup = {};
	// netns_id -1: look up in the skb's own network namespace.
	struct bpf_ct_opts___local opts = { .netns_id = -1, .l4proto = IPPROTO_TCP };
	struct nf_conn *ct;

	tup.ipv4.saddr = saddr;
	tup.ipv4.daddr = daddr;
	ct = bpf_skb_ct_lookup(skb, &tup, sizeof(tup.ipv4), &opts, sizeof(opts));
	if (!ct)
		return 0;
	bpf_ct_change_timeout(ct, 1000); // new timeout, in milliseconds
	bpf_ct_release(ct);
	return 1;
}

SEC("tc_cls")
int handle_kfunc(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;

	if ((void *)(eth + 1) > data_end || eth->h_proto != __builtin_bswap16(ETH_P_IP))
		return 0;
	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return 0;

	struct bpf_sock_tuple tup = {};
	// netns_id -1: look up in the skb's own network namespace.
	struct bpf_ct_opts___local opts = { .netns_id = -1, .l4proto = IPPROTO_TCP };
	tup.ipv4.saddr = ip->daddr;
	tup.ipv4.daddr = ip->saddr;
	struct nf_conn *ct = bpf_skb_ct_lookup(skb, &tup, sizeof(tup.ipv4), &opts, sizeof(opts));
	if (ct) {
		count(0);
		bpf_ct_release(ct);
	}

	if (shorten(skb, ip->saddr, ip->daddr))
		count(1);
	return 0;
}

char _license[] SEC("license") = "GPL";
