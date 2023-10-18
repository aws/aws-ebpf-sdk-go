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
  __u8  ip[4];
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

struct bpf_map_def_pvt SEC("maps") ingress_map = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size =sizeof(struct lpm_trie_key),
	.value_size = sizeof(struct lpm_trie_val[30]),
	.max_entries = 65536,
	.map_flags = BPF_F_NO_PREALLOC,
	.pinning = PIN_GLOBAL_NS,
};


SEC("tc_cls")
int handle_ingress(struct __sk_buff *skb)
{
	struct keystruct trie_key;
	struct lpm_trie_val *trie_val;
	__u32 l4_src_port = 0;
	__u32 l4_dst_port = 0;
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

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
		trie_key.ip[0] = ip->saddr & 0xff;
		trie_key.ip[1] = (ip->saddr >> 8) & 0xff;
		trie_key.ip[2] = (ip->saddr >> 16) & 0xff;
		trie_key.ip[3] = (ip->saddr >> 24) & 0xff;

		trie_val = bpf_map_lookup_elem(&ingress_map, &trie_key);
		if (trie_val == NULL) {
			return BPF_DROP;
		}

		for (int i=0; i<30; i++, trie_val++){
			if (trie_val->protocol == RESERVED_IP_PROTOCOL) {
				return BPF_DROP;
			}

			if ((trie_val->protocol == ANY_IP_PROTOCOL) || (trie_val->protocol == ip->protocol &&
						((trie_val->start_port == ANY_PORT) || (l4_dst_port == trie_val->start_port) ||
						 (l4_dst_port > trie_val->start_port && l4_dst_port <= trie_val->end_port)))) {
				return BPF_OK;
			}
		}

		return BPF_OK;

	}
	return BPF_DROP;
}

char _license[] SEC("license") = "GPL";
