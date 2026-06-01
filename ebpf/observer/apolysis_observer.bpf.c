// SPDX-License-Identifier: GPL-2.0-only

/*
 * Audit-only observer skeleton for M4.
 *
 * This source defines the ring-buffer ABI and attach points that the Rust
 * userspace loader plans to consume. The prebuilt CO-RE object is not checked
 * in yet; M4 tests exercise the userspace ring-buffer pipeline with fixture
 * records so normal development does not require root or CAP_BPF.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/apolysis_observer.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} APOLYSIS_EVENTS SEC(".maps");

static __always_inline struct apolysis_kernel_event *reserve_event(unsigned int kind)
{
    struct apolysis_kernel_event *event;

    event = bpf_ringbuf_reserve(&APOLYSIS_EVENTS, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    event->gid = bpf_get_current_uid_gid() >> 32;
    event->event_kind = kind;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    return event;
}

SEC("tracepoint/sched/sched_process_exec")
int apolysis_sched_process_exec(void *ctx)
{
    struct apolysis_kernel_event *event;

    event = reserve_event(APOLYSIS_EVENT_EXEC);
    if (!event)
        return 0;

    __builtin_memcpy(event->action, "exec", 5);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int apolysis_sys_enter_openat(void *ctx)
{
    struct apolysis_kernel_event *event;

    event = reserve_event(APOLYSIS_EVENT_OPEN);
    if (!event)
        return 0;

    __builtin_memcpy(event->action, "read", 5);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int apolysis_sys_enter_openat2(void *ctx)
{
    struct apolysis_kernel_event *event;

    event = reserve_event(APOLYSIS_EVENT_OPEN);
    if (!event)
        return 0;

    __builtin_memcpy(event->action, "read", 5);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int apolysis_sys_enter_connect(void *ctx)
{
    struct apolysis_kernel_event *event;

    event = reserve_event(APOLYSIS_EVENT_CONNECT);
    if (!event)
        return 0;

    __builtin_memcpy(event->action, "connect", 8);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int apolysis_sys_enter_creat(void *ctx)
{
    struct apolysis_kernel_event *event;

    event = reserve_event(APOLYSIS_EVENT_CREATE);
    if (!event)
        return 0;

    __builtin_memcpy(event->action, "create", 7);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int apolysis_sys_enter_truncate(void *ctx)
{
    struct apolysis_kernel_event *event;

    event = reserve_event(APOLYSIS_EVENT_TRUNCATE);
    if (!event)
        return 0;

    __builtin_memcpy(event->action, "truncate", 9);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int apolysis_sys_enter_unlinkat(void *ctx)
{
    struct apolysis_kernel_event *event;

    event = reserve_event(APOLYSIS_EVENT_UNLINK);
    if (!event)
        return 0;

    __builtin_memcpy(event->action, "unlink", 7);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int apolysis_sys_enter_renameat2(void *ctx)
{
    struct apolysis_kernel_event *event;

    event = reserve_event(APOLYSIS_EVENT_RENAME);
    if (!event)
        return 0;

    __builtin_memcpy(event->action, "rename", 7);
    bpf_ringbuf_submit(event, 0);
    return 0;
}
