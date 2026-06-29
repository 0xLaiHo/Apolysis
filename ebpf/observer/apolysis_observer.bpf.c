// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/apolysis_observer.h"

char LICENSE[] SEC("license") = "GPL";

#define APOLYSIS_O_ACCMODE 00000003
#define APOLYSIS_O_CREAT 00000100
#define APOLYSIS_O_TRUNC 00001000

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} APOLYSIS_EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct apolysis_scope_config);
} APOLYSIS_CONFIG SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned int);
    __type(value, unsigned char);
} APOLYSIS_TRACKED_PIDS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, unsigned long long);
    __type(value, unsigned char);
} APOLYSIS_TRACKED_CGROUPS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct apolysis_observer_counters);
} APOLYSIS_COUNTERS SEC(".maps");

static __always_inline struct apolysis_observer_counters *observer_counters(void)
{
    unsigned int key = 0;

    return bpf_map_lookup_elem(&APOLYSIS_COUNTERS, &key);
}

static __always_inline void count_reserve_failure(void)
{
    struct apolysis_observer_counters *counters = observer_counters();

    if (counters)
        __sync_fetch_and_add(&counters->reserve_failures, 1);
}

static __always_inline void count_map_pressure(void)
{
    struct apolysis_observer_counters *counters = observer_counters();

    if (counters)
        __sync_fetch_and_add(&counters->map_pressure, 1);
}

static __always_inline struct apolysis_scope_config *scope_config(void)
{
    unsigned int key = 0;

    return bpf_map_lookup_elem(&APOLYSIS_CONFIG, &key);
}

static __always_inline bool pid_is_tracked(unsigned int pid)
{
    return bpf_map_lookup_elem(&APOLYSIS_TRACKED_PIDS, &pid) != 0;
}

static __always_inline bool current_pid_tree_is_tracked(void)
{
    unsigned long long pid_tgid;
    unsigned int tgid;
    unsigned int tid;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;
    tid = pid_tgid;
    return pid_is_tracked(tgid) || pid_is_tracked(tid);
}

static __always_inline bool current_is_in_scope(void)
{
    struct apolysis_scope_config *config = scope_config();
    unsigned long long cgroup_id;

    if (!config)
        return false;

    if (config->mode == APOLYSIS_SCOPE_CGROUP)
        return config->cgroup_id == bpf_get_current_cgroup_id();

    if (config->mode == APOLYSIS_SCOPE_MULTI_CGROUP) {
        cgroup_id = bpf_get_current_cgroup_id();
        return bpf_map_lookup_elem(&APOLYSIS_TRACKED_CGROUPS, &cgroup_id) != 0;
    }

    if (config->mode != APOLYSIS_SCOPE_PID_TREE)
        return false;

    return current_pid_tree_is_tracked();
}

static __always_inline unsigned int current_parent_pid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    return BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline struct apolysis_kernel_event *reserve_event(unsigned int kind)
{
    struct apolysis_kernel_event *event;
    unsigned long long pid_tgid;
    unsigned long long uid_gid;

    if (!current_is_in_scope())
        return 0;

    event = bpf_ringbuf_reserve(&APOLYSIS_EVENTS, sizeof(*event), 0);
    if (!event) {
        count_reserve_failure();
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->pid = pid_tgid >> 32;
    event->ppid = current_parent_pid();
    event->uid = uid_gid;
    event->gid = uid_gid >> 32;
    event->event_kind = kind;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    return event;
}

static __always_inline void copy_action(struct apolysis_kernel_event *event,
                                        const char *action,
                                        unsigned int length)
{
    __builtin_memcpy(event->action, action, length);
}

static __always_inline void read_user_path(struct apolysis_kernel_event *event,
                                           const char *path)
{
    long length;

    length = bpf_probe_read_user_str(event->resource, sizeof(event->resource), path);
    if (length == sizeof(event->resource))
        event->flags |= APOLYSIS_FLAG_RESOURCE_TRUNCATED;
}

static __always_inline void read_kernel_path(struct apolysis_kernel_event *event,
                                             const char *path)
{
    long length;

    length = bpf_probe_read_kernel_str(event->resource, sizeof(event->resource), path);
    if (length == sizeof(event->resource))
        event->flags |= APOLYSIS_FLAG_RESOURCE_TRUNCATED;
}

static __always_inline unsigned int open_event_kind(unsigned long long flags)
{
    if (flags & APOLYSIS_O_CREAT)
        return APOLYSIS_EVENT_CREATE;
    if (flags & APOLYSIS_O_TRUNC)
        return APOLYSIS_EVENT_TRUNCATE;
    return APOLYSIS_EVENT_OPEN;
}

static __always_inline void copy_open_action(struct apolysis_kernel_event *event,
                                             unsigned long long flags)
{
    if (flags & APOLYSIS_O_CREAT)
        copy_action(event, "create", 7);
    else if (flags & APOLYSIS_O_TRUNC)
        copy_action(event, "truncate", 9);
    else if (flags & APOLYSIS_O_ACCMODE)
        copy_action(event, "write", 6);
    else
        copy_action(event, "read", 5);
}

SEC("tracepoint/sched/sched_process_fork")
int apolysis_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct apolysis_scope_config *config = scope_config();
    struct apolysis_kernel_event *event;
    unsigned int child_pid;
    unsigned char tracked = 1;

    if (!config)
        return 0;

    if (config->mode == APOLYSIS_SCOPE_PID_TREE) {
        if (!pid_is_tracked(ctx->parent_pid) && !current_pid_tree_is_tracked())
            return 0;
        child_pid = ctx->child_pid;
        if (bpf_map_update_elem(&APOLYSIS_TRACKED_PIDS, &child_pid, &tracked, BPF_NOEXIST))
            count_map_pressure();
    } else if (!current_is_in_scope()) {
        return 0;
    }

    event = reserve_event(APOLYSIS_EVENT_FORK);
    if (!event)
        return 0;

    event->pid = ctx->child_pid;
    event->ppid = ctx->parent_pid;
    copy_action(event, "fork", 5);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int apolysis_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct apolysis_kernel_event *event;
    const char *filename;

    event = reserve_event(APOLYSIS_EVENT_EXEC);
    if (!event)
        return 0;

    filename = (const char *)ctx + (ctx->__data_loc_filename & 0xffff);
    read_kernel_path(event, filename);
    copy_action(event, "exec", 5);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int apolysis_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    struct apolysis_scope_config *config = scope_config();
    struct apolysis_kernel_event *event;
    unsigned int pid;

    event = reserve_event(APOLYSIS_EVENT_EXIT);
    if (event) {
        event->pid = ctx->pid;
        bpf_probe_read_kernel(event->comm, sizeof(event->comm), ctx->comm);
        copy_action(event, "exit", 5);
        bpf_ringbuf_submit(event, 0);
    }

    if (config && config->mode == APOLYSIS_SCOPE_PID_TREE) {
        pid = ctx->pid;
        bpf_map_delete_elem(&APOLYSIS_TRACKED_PIDS, &pid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int apolysis_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long long flags = ctx->args[2];
    struct apolysis_kernel_event *event = reserve_event(open_event_kind(flags));

    if (!event)
        return 0;
    read_user_path(event, (const char *)ctx->args[1]);
    copy_open_action(event, flags);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int apolysis_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long long flags = 0;
    struct apolysis_kernel_event *event;

    bpf_probe_read_user(&flags, sizeof(flags), (const void *)ctx->args[2]);
    event = reserve_event(open_event_kind(flags));

    if (!event)
        return 0;
    read_user_path(event, (const char *)ctx->args[1]);
    copy_open_action(event, flags);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int apolysis_sys_enter_creat(struct trace_event_raw_sys_enter *ctx)
{
    struct apolysis_kernel_event *event = reserve_event(APOLYSIS_EVENT_CREATE);

    if (!event)
        return 0;
    read_user_path(event, (const char *)ctx->args[0]);
    copy_action(event, "create", 7);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int apolysis_sys_enter_truncate(struct trace_event_raw_sys_enter *ctx)
{
    struct apolysis_kernel_event *event = reserve_event(APOLYSIS_EVENT_TRUNCATE);

    if (!event)
        return 0;
    read_user_path(event, (const char *)ctx->args[0]);
    copy_action(event, "truncate", 9);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int apolysis_sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct apolysis_kernel_event *event = reserve_event(APOLYSIS_EVENT_UNLINK);

    if (!event)
        return 0;
    read_user_path(event, (const char *)ctx->args[1]);
    copy_action(event, "unlink", 7);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int apolysis_sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    struct apolysis_kernel_event *event = reserve_event(APOLYSIS_EVENT_RENAME);
    long length;

    if (!event)
        return 0;
    read_user_path(event, (const char *)ctx->args[1]);
    length = bpf_probe_read_user_str(event->payload, sizeof(event->payload),
                                     (const char *)ctx->args[3]);
    if (length == sizeof(event->payload))
        event->flags |= APOLYSIS_FLAG_PAYLOAD_TRUNCATED;
    copy_action(event, "rename", 7);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int apolysis_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct apolysis_kernel_event *event = reserve_event(APOLYSIS_EVENT_CONNECT);
    unsigned long long length;

    if (!event)
        return 0;

    length = ctx->args[2];
    if (length > sizeof(event->payload)) {
        length = sizeof(event->payload);
        event->flags |= APOLYSIS_FLAG_PAYLOAD_TRUNCATED;
    }
    if (bpf_probe_read_user(event->payload, length, (const void *)ctx->args[1]) == 0)
        event->flags |= APOLYSIS_FLAG_PAYLOAD_SOCKADDR;
    copy_action(event, "connect", 8);
    bpf_ringbuf_submit(event, 0);
    return 0;
}
