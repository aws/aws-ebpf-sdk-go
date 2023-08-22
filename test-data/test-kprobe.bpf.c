#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("kprobe/oom_kill_process")
int oom_kill(struct pt_regs *ctx) {
	return 0;
}


char _license[] SEC("license") = "GPL";