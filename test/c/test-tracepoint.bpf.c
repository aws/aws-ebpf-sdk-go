#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct sched_process_fork_t {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char parent_comm[16];
    u32 parent_pid;
    char child_comm[16];
    u32 child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int sched_process_fork(struct sched_process_fork_t *ctx) {
    return 0;
}