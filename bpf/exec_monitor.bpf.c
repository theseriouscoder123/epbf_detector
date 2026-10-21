// SPDX-License-Identifier: GPL-2.0
// Minimal exec monitor: attaches to sched_process_exec tracepoint (CO-RE),
// captures pid/ppid/comm/parent_comm, pushes to a ring buffer.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

struct event {
	__u32 pid;
	__u32 ppid;
	char comm[TASK_COMM_LEN];
	char parent_comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline void fill_and_submit(void)
{
	struct event *e;
	struct task_struct *task;
	struct task_struct *parent;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	task = (struct task_struct *)bpf_get_current_task();
	parent = BPF_CORE_READ(task, real_parent);

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(parent, tgid);

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	BPF_CORE_READ_STR_INTO(&e->parent_comm, parent, comm);

	bpf_ringbuf_submit(e, 0);
}

// Primary attach point: sched_process_exec tracepoint.
SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_sched_process_exec, struct task_struct *p,
	     pid_t old_pid, struct linux_binprm *bprm)
{
	fill_and_submit();
	return 0;
}

// Fallback attach point if tp_btf/sched_process_exec is unavailable:
// raw execve syscall entry. Kept as a separate program; the Go agent
// tries the tracepoint first and only loads/attaches this one on failure.
SEC("tracepoint/syscalls/sys_enter_execve")
int on_sys_enter_execve(void *ctx)
{
	fill_and_submit();
	return 0;
}
