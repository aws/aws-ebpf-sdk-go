#include <linux/types.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe")
int test_kprobe(struct pt_regs *ctx) { return 0; }

char _license[] SEC("license") = "GPL";
