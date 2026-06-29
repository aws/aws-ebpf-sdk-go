#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// A __noinline subprogram that touches NO map and needs no relocation. clang
// emits it into .text but produces NO .rel.text section (nothing to relocate
// inside .text). This exercises the "No .rel.text relocation section found"
// path in getRelocatedTextSection: .text is non-empty and must still be read
// and appended, but with no map relocations applied.
static __attribute__((noinline)) int classify_len(__u32 len)
{
    if (len > 1500)
        return 3;
    if (len > 500)
        return 2;
    if (len > 0)
        return 1;
    return 0;
}

SEC("tc_cls")
int handle_ingress(struct __sk_buff *skb)
{
    if (classify_len(skb->len) > 0)
        return BPF_OK;
    return BPF_DROP;
}

char _license[] SEC("license") = "GPL";
