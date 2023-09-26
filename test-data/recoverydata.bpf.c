#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_F_NO_PREALLOC 1
#define PIN_GLOBAL_NS           2

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct lpm_trie_key {
    __u32 prefixlen;
    __u8 ip[4];
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
};

struct conntrack_value {
   __u8 val[4];
};

struct bpf_map_def_pvt SEC("maps") ingress_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size =sizeof(struct lpm_trie_key),
    .value_size = sizeof(struct lpm_trie_val[16]),
    .max_entries = 100,
    .map_flags = BPF_F_NO_PREALLOC,
    .pinning = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt SEC("maps") aws_conntrack_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size =sizeof(struct conntrack_key),
    .value_size = sizeof(struct conntrack_value),
    .max_entries = 65536,
    .pinning = PIN_GLOBAL_NS,
};


SEC("tc_cls")
int handle_ingress(struct __sk_buff *skb)
{
	struct lpm_trie_key trie_key;
	trie_key.prefixlen = 32;
	trie_key.ip[0] = 10; 
	trie_key.ip[1] = 1;
	trie_key.ip[2] = 1;
	trie_key.ip[3] = 100;

	struct lpm_trie_val *trie_val;
	trie_val = bpf_map_lookup_elem(&ingress_map, &trie_key);
	if (trie_val == NULL) {
		return BPF_DROP;
	}
	return BPF_OK;
}

SEC("kprobe/nf_ct_delete")
int conn_del(struct pt_regs *ctx) {
	struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);	
  	struct nf_conn new_ct = {};
  	bpf_probe_read(&new_ct, sizeof(new_ct), ct);
  	struct conntrack_key flow_key = {};
  	__builtin_memset(&flow_key, 0, sizeof(flow_key));

  	struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
  	bpf_probe_read(&tuplehash, sizeof(tuplehash), &new_ct.tuplehash);

 	bpf_probe_read(&flow_key.src_ip, sizeof(flow_key.src_ip), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip);
  	bpf_probe_read(&flow_key.src_port, sizeof(flow_key.src_port), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all);
  	bpf_probe_read(&flow_key.dest_ip, sizeof(flow_key.dest_ip), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip);
  	bpf_probe_read(&flow_key.dest_port, sizeof(flow_key.dest_port), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all);
  	bpf_probe_read(&flow_key.protocol, sizeof(flow_key.protocol), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum);

	return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int sched_process_fork(void *ctx) {
    return 0;
}

char _license[] SEC("license") = "GPL";
