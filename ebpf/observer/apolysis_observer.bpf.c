// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../include/apolysis_observer.h"
#include "../include/apolysis_intent.h"

char LICENSE[] SEC("license") = "GPL";

#define APOLYSIS_O_ACCMODE 00000003
#define APOLYSIS_O_CREAT 00000100
#define APOLYSIS_O_TRUNC 00001000
#define APOLYSIS_EXEC_ARGC_LIMIT 8
#define APOLYSIS_EXEC_ARG_LEN 32

struct apolysis_pending_exec {
    unsigned int flags;
    unsigned int intent_capture_complete;
    char resource[APOLYSIS_RESOURCE_LEN];
    char payload[APOLYSIS_PAYLOAD_LEN];
    char intent_id[APOLYSIS_INTENT_ID_LEN];
};

struct apolysis_intent_context {
    unsigned long long start_time_ns;
    char intent_id[APOLYSIS_INTENT_ID_LEN];
};

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
    __uint(max_entries, 4096);
    __type(key, unsigned long long);
    __type(value, struct apolysis_pending_exec);
} APOLYSIS_PENDING_EXECS SEC(".maps");

/* Attribution is inherited before ring-buffer delivery. A dropped fork/exec
 * notification must not make later events use an older tool's attribution. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned int);
    __type(value, struct apolysis_intent_context);
} APOLYSIS_INTENT_CONTEXTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct apolysis_pending_exec);
} APOLYSIS_EXEC_SCRATCH SEC(".maps");

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

static __always_inline unsigned long long process_start_time(struct task_struct *task)
{
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);

    return BPF_CORE_READ(leader, start_boottime);
}

static __always_inline void fill_process_identity(struct apolysis_kernel_event *event)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    struct apolysis_intent_context *intent;
    unsigned int pid = event->pid;

    event->process_start_time_ns = process_start_time(task);
    event->parent_start_time_ns = process_start_time(parent);
    intent = bpf_map_lookup_elem(&APOLYSIS_INTENT_CONTEXTS, &pid);
    if (intent && intent->start_time_ns &&
        intent->start_time_ns == event->process_start_time_ns)
        __builtin_memcpy(event->intent_id, intent->intent_id, sizeof(event->intent_id));
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
    fill_process_identity(event);
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

static __always_inline void read_pending_user_path(struct apolysis_pending_exec *pending,
                                                   const char *path)
{
    long length;

    length = bpf_probe_read_user_str(pending->resource, sizeof(pending->resource), path);
    if (length <= 0 || length == sizeof(pending->resource))
        pending->flags |= APOLYSIS_FLAG_RESOURCE_TRUNCATED;
}

static __always_inline void append_exec_argv_arg(struct apolysis_pending_exec *pending,
                                                 unsigned int *offset,
                                                 const char *arg)
{
    unsigned int off = *offset;
    long length;

    if (off >= sizeof(pending->payload) - APOLYSIS_EXEC_ARG_LEN) {
        pending->flags |= APOLYSIS_FLAG_ARGV_TRUNCATED | APOLYSIS_FLAG_PAYLOAD_TRUNCATED;
        return;
    }

    if (off > 5) {
        pending->payload[off] = ' ';
        off += 1;
    }

    /* Pin the offset in one register and re-bound it right before the read.
     * Some clang/kernel pairs otherwise clamp a copy of the offset while the
     * pointer arithmetic uses the unclamped original, and the verifier
     * rejects payload + off + APOLYSIS_EXEC_ARG_LEN as out of range. */
    asm volatile("" : "+r"(off));
    if (off > sizeof(pending->payload) - APOLYSIS_EXEC_ARG_LEN) {
        pending->flags |= APOLYSIS_FLAG_ARGV_TRUNCATED | APOLYSIS_FLAG_PAYLOAD_TRUNCATED;
        *offset = off;
        return;
    }

    length = bpf_probe_read_user_str(pending->payload + off, APOLYSIS_EXEC_ARG_LEN, arg);
    if (length < 0) {
        pending->flags |= APOLYSIS_FLAG_ARGV_TRUNCATED;
        *offset = off;
        return;
    }

    if (length == APOLYSIS_EXEC_ARG_LEN) {
        pending->flags |= APOLYSIS_FLAG_ARGV_TRUNCATED | APOLYSIS_FLAG_PAYLOAD_TRUNCATED;
        *offset = off + APOLYSIS_EXEC_ARG_LEN - 1;
        return;
    }

    if (length > 0)
        off += length - 1;
    *offset = off;
}

static __always_inline bool executable_is_shell(const char *path)
{
    unsigned int base = 0;
    unsigned int length = 0;
    unsigned int i;

    for (i = 0; i < APOLYSIS_RESOURCE_LEN; i++) {
        char ch = path[i];
        if (!ch)
            break;
        if (ch == '/')
            base = i + 1;
        length = i + 1;
    }
    if (base > APOLYSIS_RESOURCE_LEN - 5)
        return false;
    length -= base;
    if (length == 2)
        return path[base] == 's' && path[base + 1] == 'h';
    if (length == 3)
        return (path[base] == 'z' || path[base] == 'k' || path[base] == 'a') &&
               path[base + 1] == 's' && path[base + 2] == 'h';
    if (length == 4)
        return ((path[base] == 'b' || path[base] == 'd') &&
                path[base + 1] == 'a' && path[base + 2] == 's' && path[base + 3] == 'h') ||
               (path[base] == 'f' && path[base + 1] == 'i' &&
                path[base + 2] == 's' && path[base + 3] == 'h');
    return false;
}

/* This is a complete comment header, not a search through diagnostic argv.
 * The hook places it at the beginning of the shell's command-string argument.
 * Reading exactly the header also works when the remaining command is long. */
static __always_inline void read_intent_header(struct apolysis_pending_exec *pending,
                                               const char *command)
{
    char header[APOLYSIS_INTENT_HEADER_LEN + 1] = {};
    long length = bpf_probe_read_user_str(header, sizeof(header), command);
    int capture;

    if (length <= 0)
        return;
    capture = apolysis_parse_intent_header(header, length - 1, pending->intent_id);
    pending->intent_capture_complete = capture != APOLYSIS_INTENT_UNKNOWN;

}

static __always_inline void read_exec_argv(struct apolysis_pending_exec *pending,
                                           const char *const *argv)
{
    const char *arg = 0;
    unsigned int offset = 5;
    bool shell = executable_is_shell(pending->resource);
    bool command_next = false;
    bool command_seen = false;
    bool unknown_options = false;
    int i;

    __builtin_memcpy(pending->payload, "argv:", 5);
    if (!shell && !(pending->flags & APOLYSIS_FLAG_RESOURCE_TRUNCATED))
        pending->intent_capture_complete = 1;

#pragma unroll
    for (i = 0; i < APOLYSIS_EXEC_ARGC_LIMIT; i++) {
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) < 0) {
            pending->flags |= APOLYSIS_FLAG_ARGV_TRUNCATED;
            return;
        }
        if (!arg) {
            if (shell && !command_seen && !command_next && !unknown_options)
                pending->intent_capture_complete = 1;
            return;
        }
        if (shell && !command_seen && i > 0) {
            char option[4] = {};
            if (command_next) {
                read_intent_header(pending, arg);
                command_seen = true;
            } else if (bpf_probe_read_user_str(option, sizeof(option), arg) > 0) {
                if (option[0] != '-' || (option[1] == '-' && option[2] == '\0')) {
                    /* A script filename or -- ends option parsing. Later -c
                     * arguments belong to the script, not to the shell. */
                    command_seen = true;
                    pending->intent_capture_complete = !unknown_options;
                }
                command_next = option[0] == '-' &&
                    ((option[1] == 'c' && option[2] == '\0') ||
                     (option[1] == 'l' && option[2] == 'c' && option[3] == '\0') ||
                     (option[1] == 'c' && option[2] == 'l' && option[3] == '\0'));
                if (option[0] == '-' && !command_next)
                    unknown_options = true;
            } else {
                command_seen = true; /* unreadable option: leave capture unknown */
            }
        }
        append_exec_argv_arg(pending, &offset, arg);
    }

    if (bpf_probe_read_user(&arg, sizeof(arg), &argv[APOLYSIS_EXEC_ARGC_LIMIT]) == 0 && arg)
        pending->flags |= APOLYSIS_FLAG_ARGV_TRUNCATED;
}

static __always_inline int capture_exec_enter(const char *filename,
                                              const char *const *argv)
{
    struct apolysis_pending_exec *pending;
    unsigned long long pid_tgid;
    unsigned int scratch_key = 0;

    if (!current_is_in_scope())
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    /* A previous failed exec must not be mistaken for this attempt. */
    bpf_map_delete_elem(&APOLYSIS_PENDING_EXECS, &pid_tgid);
    pending = bpf_map_lookup_elem(&APOLYSIS_EXEC_SCRATCH, &scratch_key);
    if (!pending) {
        count_map_pressure();
        return 0;
    }

    __builtin_memset(pending, 0, sizeof(*pending));
    read_pending_user_path(pending, filename);
    read_exec_argv(pending, argv);

    if (bpf_map_update_elem(&APOLYSIS_PENDING_EXECS, &pid_tgid, pending, BPF_ANY)) {
        bpf_map_delete_elem(&APOLYSIS_PENDING_EXECS, &pid_tgid);
        count_map_pressure();
    }
    return 0;
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

SEC("raw_tracepoint/sched_process_fork")
int apolysis_sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];
    struct apolysis_scope_config *config = scope_config();
    struct apolysis_kernel_event *event;
    struct apolysis_intent_context *parent_intent;
    struct apolysis_intent_context inherited = {};
    unsigned int parent_pid = BPF_CORE_READ(parent, tgid);
    unsigned int child_pid = BPF_CORE_READ(child, tgid);
    unsigned long long parent_start = process_start_time(parent);
    unsigned long long child_start = process_start_time(child);
    unsigned char tracked = 1;

    /* Threads share their TGID's context. Do not create an entry keyed by TID. */
    if (!config || parent_pid == child_pid)
        return 0;
    if (config->mode == APOLYSIS_SCOPE_PID_TREE) {
        if (!pid_is_tracked(parent_pid) && !current_pid_tree_is_tracked())
            return 0;
        if (bpf_map_update_elem(&APOLYSIS_TRACKED_PIDS, &child_pid, &tracked, BPF_ANY))
            count_map_pressure();
    } else if (!current_is_in_scope()) {
        return 0;
    }

    parent_intent = bpf_map_lookup_elem(&APOLYSIS_INTENT_CONTEXTS, &parent_pid);
    if (parent_intent && parent_start && child_start &&
        parent_intent->start_time_ns == parent_start) {
        inherited.start_time_ns = child_start;
        __builtin_memcpy(inherited.intent_id, parent_intent->intent_id,
                         sizeof(inherited.intent_id));
        if (bpf_map_update_elem(&APOLYSIS_INTENT_CONTEXTS, &child_pid, &inherited, BPF_ANY)) {
            bpf_map_delete_elem(&APOLYSIS_INTENT_CONTEXTS, &child_pid);
            count_map_pressure();
        }
    } else {
        bpf_map_delete_elem(&APOLYSIS_INTENT_CONTEXTS, &child_pid);
    }

    event = reserve_event(APOLYSIS_EVENT_FORK);
    if (!event)
        return 0;
    event->pid = child_pid;
    event->ppid = parent_pid;
    event->process_start_time_ns = child_start;
    event->parent_start_time_ns = parent_start;
    __builtin_memset(event->intent_id, 0, sizeof(event->intent_id));
    parent_intent = bpf_map_lookup_elem(&APOLYSIS_INTENT_CONTEXTS, &child_pid);
    if (parent_intent && parent_intent->start_time_ns == child_start)
        __builtin_memcpy(event->intent_id, parent_intent->intent_id, sizeof(event->intent_id));
    copy_action(event, "fork", 5);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int apolysis_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct apolysis_kernel_event *event;
    struct apolysis_pending_exec *pending;
    struct apolysis_intent_context intent = {};
    const char *filename;
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    unsigned int pid = pid_tgid >> 32;
    /* A non-leader exec changes TID during de_thread(); old_pid identifies the
     * matching sys_enter_execve capture without mixing concurrent threads. */
    unsigned long long pending_key = ((unsigned long long)pid << 32) | (unsigned int)ctx->old_pid;

    if (!current_is_in_scope())
        return 0;
    if ((unsigned int)ctx->old_pid != pid) {
        struct apolysis_scope_config *config = scope_config();
        unsigned int old_tid = ctx->old_pid;
        if (config && config->mode == APOLYSIS_SCOPE_PID_TREE)
            bpf_map_delete_elem(&APOLYSIS_TRACKED_PIDS, &old_tid);
    }
    pending = bpf_map_lookup_elem(&APOLYSIS_PENDING_EXECS, &pending_key);
    int update = apolysis_intent_update_for_capture(pending != 0,
        pending ? pending->intent_capture_complete : 0,
        pending ? pending->intent_id[0] : 0);
    if (update == APOLYSIS_INTENT_CLEAR) {
        bpf_map_delete_elem(&APOLYSIS_INTENT_CONTEXTS, &pid);
    } else if (update == APOLYSIS_INTENT_REPLACE && pending) {
        intent.start_time_ns = process_start_time(task);
        __builtin_memcpy(intent.intent_id, pending->intent_id, sizeof(intent.intent_id));
        if (bpf_map_update_elem(&APOLYSIS_INTENT_CONTEXTS, &pid, &intent, BPF_ANY)) {
            /* Never keep the previous tool's token after a failed replacement. */
            bpf_map_delete_elem(&APOLYSIS_INTENT_CONTEXTS, &pid);
            count_map_pressure();
        }
    }
    event = reserve_event(APOLYSIS_EVENT_EXEC);
    if (!event) {
        bpf_map_delete_elem(&APOLYSIS_PENDING_EXECS, &pending_key);
        return 0;
    }
    if (update == APOLYSIS_INTENT_CLEAR)
        event->flags |= APOLYSIS_FLAG_INTENT_INCOMPLETE | APOLYSIS_FLAG_PAYLOAD_TRUNCATED;
    filename = (const char *)ctx + (ctx->__data_loc_filename & 0xffff);
    if (pending) {
        __builtin_memcpy(event->resource, pending->resource, sizeof(event->resource));
        __builtin_memcpy(event->payload, pending->payload, sizeof(event->payload));
        event->flags |= pending->flags;
    } else {
        read_kernel_path(event, filename);
    }
    bpf_map_delete_elem(&APOLYSIS_PENDING_EXECS, &pending_key);
    copy_action(event, "exec", 5);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int apolysis_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    return capture_exec_enter((const char *)ctx->args[0],
                              (const char *const *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int apolysis_sys_enter_execveat(struct trace_event_raw_sys_enter *ctx)
{
    return capture_exec_enter((const char *)ctx->args[1],
                              (const char *const *)ctx->args[2]);
}

SEC("tracepoint/sched/sched_process_exit")
int apolysis_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct apolysis_scope_config *config = scope_config();
    struct apolysis_kernel_event *event;
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    unsigned int pid = pid_tgid >> 32;
    unsigned int tid = pid_tgid;

    bpf_map_delete_elem(&APOLYSIS_PENDING_EXECS, &pid_tgid);
    /* Attach-time discovery may have seeded TIDs before this observer started.
     * Remove exited TID scope entries without deleting the live TGID context. */
    if (config && config->mode == APOLYSIS_SCOPE_PID_TREE && tid != pid)
        bpf_map_delete_elem(&APOLYSIS_TRACKED_PIDS, &tid);
    /* sched_process_exit runs after do_exit decrements signal->live. A leader
     * can exit while other threads still use the group's attribution. */
    if (BPF_CORE_READ(task, signal, live.counter) != 0)
        return 0;
    event = reserve_event(APOLYSIS_EVENT_EXIT);
    if (event) {
        copy_action(event, "exit", 5);
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&APOLYSIS_INTENT_CONTEXTS, &pid);
    if (config && config->mode == APOLYSIS_SCOPE_PID_TREE)
        bpf_map_delete_elem(&APOLYSIS_TRACKED_PIDS, &pid);
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
