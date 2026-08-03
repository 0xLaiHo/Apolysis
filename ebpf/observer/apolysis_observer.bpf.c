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
#define APOLYSIS_EXEC_ARGC_LIMIT 8
#define APOLYSIS_EXEC_ARG_LEN 32
#define APOLYSIS_AF_INET 2
#define APOLYSIS_AF_INET6 10

struct apolysis_pending_exec {
    unsigned int flags;
    char resource[APOLYSIS_RESOURCE_LEN];
    char payload[APOLYSIS_PAYLOAD_LEN];
};

struct apolysis_pending_connect {
    unsigned long long cgroup_id;
    unsigned int flags;
    unsigned char payload[APOLYSIS_PAYLOAD_LEN];
};

enum apolysis_file_syscall_source {
    APOLYSIS_FILE_SOURCE_OPENAT = 1,
    APOLYSIS_FILE_SOURCE_OPENAT2 = 2,
    APOLYSIS_FILE_SOURCE_CREAT = 3,
    APOLYSIS_FILE_SOURCE_TRUNCATE = 4,
    APOLYSIS_FILE_SOURCE_UNLINKAT = 5,
    APOLYSIS_FILE_SOURCE_RENAMEAT2 = 6,
};

struct apolysis_pending_file {
    unsigned long long cgroup_id;
    unsigned int event_kind;
    unsigned int source;
    unsigned int flags;
    char resource[APOLYSIS_RESOURCE_LEN];
    char action[APOLYSIS_ACTION_LEN];
    char payload[APOLYSIS_PAYLOAD_LEN];
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
    __type(key, unsigned int);
    __type(value, struct apolysis_pending_exec);
} APOLYSIS_PENDING_EXECS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct apolysis_pending_exec);
} APOLYSIS_EXEC_SCRATCH SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned long long);
    __type(value, struct apolysis_pending_connect);
} APOLYSIS_PENDING_CONNECTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct apolysis_pending_connect);
} APOLYSIS_CONNECT_SCRATCH SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, unsigned long long);
    __type(value, struct apolysis_pending_file);
} APOLYSIS_PENDING_FILES SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, struct apolysis_pending_file);
} APOLYSIS_FILE_SCRATCH SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, unsigned long long);
    __type(value, unsigned char);
} APOLYSIS_TRACKED_CGROUPS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, unsigned long long);
    __type(value, struct apolysis_network_connect_counters);
} APOLYSIS_CONNECT_COUNTERS_BY_CGROUP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, unsigned long long);
    __type(value, struct apolysis_file_operation_counters);
} APOLYSIS_FILE_COUNTERS_BY_CGROUP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, unsigned long long);
    __type(value, unsigned long long);
} APOLYSIS_SCOPE_UPDATES_BY_CGROUP SEC(".maps");

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

static __always_inline unsigned char cgroup_scope_state(unsigned long long cgroup_id)
{
    unsigned char *state;

    state = bpf_map_lookup_elem(&APOLYSIS_TRACKED_CGROUPS, &cgroup_id);
    return state ? *state : 0;
}

static __always_inline struct apolysis_network_connect_counters *
network_connect_counters(unsigned long long cgroup_id)
{
    return bpf_map_lookup_elem(&APOLYSIS_CONNECT_COUNTERS_BY_CGROUP, &cgroup_id);
}

static __always_inline bool begin_scope_counter_update(unsigned long long cgroup_id)
{
    unsigned long long *updates;

    updates = bpf_map_lookup_elem(&APOLYSIS_SCOPE_UPDATES_BY_CGROUP, &cgroup_id);
    if (!updates)
        return false;
    __sync_fetch_and_add(updates, 1);
    if (cgroup_scope_state(cgroup_id) == APOLYSIS_CGROUP_ACTIVE)
        return true;
    __sync_fetch_and_sub(updates, 1);
    return false;
}

static __always_inline void end_scope_counter_update(unsigned long long cgroup_id,
                                                      bool update_scoped)
{
    unsigned long long *updates;

    if (update_scoped) {
        updates = bpf_map_lookup_elem(&APOLYSIS_SCOPE_UPDATES_BY_CGROUP, &cgroup_id);
        if (!updates)
            return;
        __sync_fetch_and_sub(updates, 1);
    }
}

static __always_inline void count_connect_missing_entry(
    unsigned long long cgroup_id,
    bool update_scoped)
{
    struct apolysis_observer_counters *counters = observer_counters();
    struct apolysis_network_connect_counters *scoped;

    if (counters)
        __sync_fetch_and_add(&counters->connect_missing_entries, 1);
    if (!update_scoped)
        return;
    scoped = network_connect_counters(cgroup_id);
    if (scoped)
        __sync_fetch_and_add(&scoped->missing_entries, 1);
}

static __always_inline void count_connect_missing_exit(
    unsigned long long cgroup_id,
    bool update_scoped)
{
    struct apolysis_observer_counters *counters = observer_counters();
    struct apolysis_network_connect_counters *scoped;

    if (counters)
        __sync_fetch_and_add(&counters->connect_missing_exits, 1);
    if (!update_scoped)
        return;
    scoped = network_connect_counters(cgroup_id);
    if (scoped)
        __sync_fetch_and_add(&scoped->missing_exits, 1);
}

static __always_inline void increment_connect_pending(
    unsigned long long cgroup_id,
    bool update_scoped)
{
    struct apolysis_observer_counters *counters = observer_counters();
    struct apolysis_network_connect_counters *scoped;

    if (counters)
        __sync_fetch_and_add(&counters->connect_pending, 1);
    if (!update_scoped)
        return;
    scoped = network_connect_counters(cgroup_id);
    if (scoped)
        __sync_fetch_and_add(&scoped->pending, 1);
}

static __always_inline void decrement_connect_pending(
    unsigned long long cgroup_id,
    bool update_scoped)
{
    struct apolysis_observer_counters *counters = observer_counters();
    struct apolysis_network_connect_counters *scoped;

    if (counters)
        __sync_fetch_and_sub(&counters->connect_pending, 1);
    if (!update_scoped)
        return;
    scoped = network_connect_counters(cgroup_id);
    if (scoped)
        __sync_fetch_and_sub(&scoped->pending, 1);
}

static __always_inline void account_stale_connect(unsigned long long cgroup_id)
{
    bool update_scoped = begin_scope_counter_update(cgroup_id);

    decrement_connect_pending(cgroup_id, update_scoped);
    count_connect_missing_exit(cgroup_id, update_scoped);
    end_scope_counter_update(cgroup_id, update_scoped);
}

static __always_inline struct apolysis_operation_pair_counters *
file_pair_counters(struct apolysis_file_operation_counters *counters,
                   unsigned int event_kind)
{
    if (!counters)
        return 0;
    switch (event_kind) {
    case APOLYSIS_EVENT_OPEN:
        return &counters->open;
    case APOLYSIS_EVENT_CREATE:
        return &counters->create;
    case APOLYSIS_EVENT_TRUNCATE:
        return &counters->truncate;
    case APOLYSIS_EVENT_UNLINK:
        return &counters->unlink;
    case APOLYSIS_EVENT_RENAME:
        return &counters->rename;
    default:
        return 0;
    }
}

static __always_inline struct apolysis_file_operation_counters *
file_operation_counters(unsigned long long cgroup_id)
{
    return bpf_map_lookup_elem(&APOLYSIS_FILE_COUNTERS_BY_CGROUP, &cgroup_id);
}

static __always_inline void count_file_missing_entry(
    unsigned long long cgroup_id,
    unsigned int event_kind,
    bool update_scoped)
{
    struct apolysis_observer_counters *counters = observer_counters();
    struct apolysis_operation_pair_counters *pair;

    if (counters) {
        pair = file_pair_counters(&counters->file_operations, event_kind);
        if (pair)
            __sync_fetch_and_add(&pair->missing_entries, 1);
    }
    if (!update_scoped)
        return;
    pair = file_pair_counters(file_operation_counters(cgroup_id), event_kind);
    if (pair)
        __sync_fetch_and_add(&pair->missing_entries, 1);
}

static __always_inline void count_file_missing_exit(
    unsigned long long cgroup_id,
    unsigned int event_kind,
    bool update_scoped)
{
    struct apolysis_observer_counters *counters = observer_counters();
    struct apolysis_operation_pair_counters *pair;

    if (counters) {
        pair = file_pair_counters(&counters->file_operations, event_kind);
        if (pair)
            __sync_fetch_and_add(&pair->missing_exits, 1);
    }
    if (!update_scoped)
        return;
    pair = file_pair_counters(file_operation_counters(cgroup_id), event_kind);
    if (pair)
        __sync_fetch_and_add(&pair->missing_exits, 1);
}

static __always_inline void increment_file_pending(
    unsigned long long cgroup_id,
    unsigned int event_kind,
    bool update_scoped)
{
    struct apolysis_observer_counters *counters = observer_counters();
    struct apolysis_operation_pair_counters *pair;

    if (counters) {
        pair = file_pair_counters(&counters->file_operations, event_kind);
        if (pair)
            __sync_fetch_and_add(&pair->pending, 1);
    }
    if (!update_scoped)
        return;
    pair = file_pair_counters(file_operation_counters(cgroup_id), event_kind);
    if (pair)
        __sync_fetch_and_add(&pair->pending, 1);
}

static __always_inline void decrement_file_pending(
    unsigned long long cgroup_id,
    unsigned int event_kind,
    bool update_scoped)
{
    struct apolysis_observer_counters *counters = observer_counters();
    struct apolysis_operation_pair_counters *pair;

    if (counters) {
        pair = file_pair_counters(&counters->file_operations, event_kind);
        if (pair)
            __sync_fetch_and_sub(&pair->pending, 1);
    }
    if (!update_scoped)
        return;
    pair = file_pair_counters(file_operation_counters(cgroup_id), event_kind);
    if (pair)
        __sync_fetch_and_sub(&pair->pending, 1);
}

static __always_inline void account_stale_file(unsigned long long cgroup_id,
                                                unsigned int event_kind)
{
    bool update_scoped = begin_scope_counter_update(cgroup_id);

    decrement_file_pending(cgroup_id, event_kind, update_scoped);
    count_file_missing_exit(cgroup_id, event_kind, update_scoped);
    end_scope_counter_update(cgroup_id, update_scoped);
}

static __always_inline struct apolysis_scope_config *scope_config(void)
{
    unsigned int key = 0;

    return bpf_map_lookup_elem(&APOLYSIS_CONFIG, &key);
}

static __always_inline bool multi_cgroup_scope(void)
{
    struct apolysis_scope_config *config = scope_config();

    return config && config->mode == APOLYSIS_SCOPE_MULTI_CGROUP;
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
        return cgroup_scope_state(cgroup_id) == APOLYSIS_CGROUP_ACTIVE;
    }

    if (config->mode != APOLYSIS_SCOPE_PID_TREE)
        return false;

    return current_pid_tree_is_tracked();
}

static __always_inline bool pair_is_in_scope(unsigned long long cgroup_id)
{
    struct apolysis_scope_config *config = scope_config();

    if (!config)
        return false;
    if (config->mode == APOLYSIS_SCOPE_CGROUP)
        return config->cgroup_id == cgroup_id &&
               bpf_get_current_cgroup_id() == cgroup_id;
    if (config->mode == APOLYSIS_SCOPE_MULTI_CGROUP)
        return cgroup_scope_state(cgroup_id) == APOLYSIS_CGROUP_ACTIVE &&
               bpf_get_current_cgroup_id() == cgroup_id;
    if (config->mode == APOLYSIS_SCOPE_PID_TREE)
        return current_pid_tree_is_tracked();
    return false;
}

static __always_inline unsigned int current_parent_pid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    return BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline struct apolysis_kernel_event *reserve_event_unchecked(unsigned int kind)
{
    struct apolysis_kernel_event *event;
    unsigned long long pid_tgid;
    unsigned long long uid_gid;

    event = bpf_ringbuf_reserve(&APOLYSIS_EVENTS, sizeof(*event), 0);
    if (!event) {
        count_reserve_failure();
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    event->abi_version = APOLYSIS_KERNEL_ABI_VERSION;
    event->record_size = sizeof(*event);
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

static __always_inline struct apolysis_kernel_event *reserve_event(unsigned int kind)
{
    if (!current_is_in_scope())
        return 0;

    return reserve_event_unchecked(kind);
}

static __always_inline struct apolysis_kernel_event *
reserve_process_event(unsigned int kind,
                      unsigned long long *cgroup_id,
                      bool *update_scoped)
{
    *cgroup_id = 0;
    *update_scoped = false;
    if (!multi_cgroup_scope())
        return reserve_event(kind);

    *cgroup_id = bpf_get_current_cgroup_id();
    *update_scoped = begin_scope_counter_update(*cgroup_id);
    if (!*update_scoped)
        return 0;
    return reserve_event_unchecked(kind);
}

static __always_inline void copy_action(struct apolysis_kernel_event *event,
                                        const char *action,
                                        unsigned int length)
{
    __builtin_memcpy(event->action, action, length);
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
    if (length == sizeof(pending->resource))
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

static __always_inline void read_exec_argv(struct apolysis_pending_exec *pending,
                                           const char *const *argv)
{
    const char *arg = 0;
    unsigned int offset = 5;
    int i;

    __builtin_memcpy(pending->payload, "argv:", 5);

#pragma unroll
    for (i = 0; i < APOLYSIS_EXEC_ARGC_LIMIT; i++) {
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) < 0) {
            pending->flags |= APOLYSIS_FLAG_ARGV_TRUNCATED;
            return;
        }
        if (!arg)
            return;
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
    unsigned int pid;
    unsigned int scratch_key = 0;

    if (!current_is_in_scope())
        return 0;

    pending = bpf_map_lookup_elem(&APOLYSIS_EXEC_SCRATCH, &scratch_key);
    if (!pending) {
        count_map_pressure();
        return 0;
    }

    __builtin_memset(pending, 0, sizeof(*pending));
    read_pending_user_path(pending, filename);
    read_exec_argv(pending, argv);

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    if (bpf_map_update_elem(&APOLYSIS_PENDING_EXECS, &pid, pending, BPF_ANY))
        count_map_pressure();
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

static __always_inline void copy_pending_file_action(
    struct apolysis_pending_file *pending,
    unsigned int event_kind,
    unsigned long long open_flags)
{
    switch (event_kind) {
    case APOLYSIS_EVENT_CREATE:
        __builtin_memcpy(pending->action, "create", 7);
        break;
    case APOLYSIS_EVENT_TRUNCATE:
        __builtin_memcpy(pending->action, "truncate", 9);
        break;
    case APOLYSIS_EVENT_UNLINK:
        __builtin_memcpy(pending->action, "unlink", 7);
        break;
    case APOLYSIS_EVENT_RENAME:
        __builtin_memcpy(pending->action, "rename", 7);
        break;
    case APOLYSIS_EVENT_OPEN:
        if (open_flags & APOLYSIS_O_ACCMODE)
            __builtin_memcpy(pending->action, "write", 6);
        else
            __builtin_memcpy(pending->action, "read", 5);
        break;
    }
}

static __always_inline void read_pending_file_path(
    struct apolysis_pending_file *pending,
    const char *path)
{
    long length;

    length = bpf_probe_read_user_str(pending->resource,
                                     sizeof(pending->resource), path);
    if (length == sizeof(pending->resource))
        pending->flags |= APOLYSIS_FLAG_RESOURCE_TRUNCATED;
}

static __always_inline int capture_file_enter(unsigned int event_kind,
                                              unsigned int source,
                                              unsigned long long open_flags,
                                              const char *path,
                                              const char *second_path)
{
    struct apolysis_pending_file *pending;
    struct apolysis_pending_file *stale;
    unsigned long long pid_tgid;
    unsigned long long cgroup_id;
    unsigned long long stale_cgroup_id = 0;
    unsigned int stale_event_kind = 0;
    unsigned int scratch_key = 0;
    bool replaces_stale_entry;
    bool update_scoped;
    long length;

    if (!current_is_in_scope())
        return 0;
    cgroup_id = bpf_get_current_cgroup_id();
    update_scoped = begin_scope_counter_update(cgroup_id);
    if (multi_cgroup_scope() && !update_scoped) {
        if (cgroup_scope_state(cgroup_id) == APOLYSIS_CGROUP_ACTIVE)
            count_map_pressure();
        return 0;
    }

    pending = bpf_map_lookup_elem(&APOLYSIS_FILE_SCRATCH, &scratch_key);
    if (!pending) {
        count_file_missing_exit(cgroup_id, event_kind, update_scoped);
        end_scope_counter_update(cgroup_id, update_scoped);
        count_map_pressure();
        return 0;
    }
    __builtin_memset(pending, 0, sizeof(*pending));
    pending->cgroup_id = cgroup_id;
    pending->event_kind = event_kind;
    pending->source = source;
    read_pending_file_path(pending, path);
    if (second_path) {
        length = bpf_probe_read_user_str(pending->payload,
                                         sizeof(pending->payload), second_path);
        if (length == sizeof(pending->payload))
            pending->flags |= APOLYSIS_FLAG_PAYLOAD_TRUNCATED;
    }
    copy_pending_file_action(pending, event_kind, open_flags);

    pid_tgid = bpf_get_current_pid_tgid();
    stale = bpf_map_lookup_elem(&APOLYSIS_PENDING_FILES, &pid_tgid);
    replaces_stale_entry = stale != 0;
    if (stale) {
        stale_cgroup_id = stale->cgroup_id;
        stale_event_kind = stale->event_kind;
    }
    if (bpf_map_update_elem(&APOLYSIS_PENDING_FILES, &pid_tgid, pending, BPF_ANY)) {
        if (replaces_stale_entry) {
            bpf_map_delete_elem(&APOLYSIS_PENDING_FILES, &pid_tgid);
            account_stale_file(stale_cgroup_id, stale_event_kind);
        }
        count_file_missing_exit(cgroup_id, event_kind, update_scoped);
        end_scope_counter_update(cgroup_id, update_scoped);
        count_map_pressure();
        return 0;
    }
    if (replaces_stale_entry)
        account_stale_file(stale_cgroup_id, stale_event_kind);
    increment_file_pending(cgroup_id, event_kind, update_scoped);
    end_scope_counter_update(cgroup_id, update_scoped);
    return 0;
}

static __always_inline void account_file_missing_entry_for_current(
    unsigned int event_kind)
{
    unsigned long long cgroup_id = bpf_get_current_cgroup_id();
    bool update_scoped;

    if (multi_cgroup_scope()) {
        update_scoped = begin_scope_counter_update(cgroup_id);
        if (update_scoped) {
            count_file_missing_entry(cgroup_id, event_kind, update_scoped);
            end_scope_counter_update(cgroup_id, update_scoped);
        }
    } else if (current_is_in_scope()) {
        count_file_missing_entry(cgroup_id, event_kind, 0);
    }
}

static __always_inline int capture_file_exit(struct trace_event_raw_sys_exit *ctx,
                                             unsigned int source,
                                             unsigned int fallback_event_kind)
{
    struct apolysis_pending_file *pending;
    struct apolysis_kernel_event *event;
    unsigned long long pid_tgid;
    unsigned long long cgroup_id;
    unsigned int event_kind;
    bool update_scoped;

    pid_tgid = bpf_get_current_pid_tgid();
    pending = bpf_map_lookup_elem(&APOLYSIS_PENDING_FILES, &pid_tgid);
    if (!pending) {
        account_file_missing_entry_for_current(fallback_event_kind);
        return 0;
    }
    cgroup_id = pending->cgroup_id;
    event_kind = pending->event_kind;
    if (pending->source != source) {
        bpf_map_delete_elem(&APOLYSIS_PENDING_FILES, &pid_tgid);
        account_stale_file(cgroup_id, event_kind);
        account_file_missing_entry_for_current(fallback_event_kind);
        return 0;
    }

    update_scoped = begin_scope_counter_update(cgroup_id);
    if (!pair_is_in_scope(cgroup_id)) {
        bpf_map_delete_elem(&APOLYSIS_PENDING_FILES, &pid_tgid);
        decrement_file_pending(cgroup_id, event_kind, update_scoped);
        count_file_missing_exit(cgroup_id, event_kind, update_scoped);
        end_scope_counter_update(cgroup_id, update_scoped);
        return 0;
    }

    event = reserve_event_unchecked(event_kind);
    if (event) {
        __builtin_memcpy(event->resource, pending->resource, sizeof(event->resource));
        __builtin_memcpy(event->action, pending->action, sizeof(event->action));
        __builtin_memcpy(event->payload, pending->payload, sizeof(event->payload));
        event->flags |= pending->flags | APOLYSIS_FLAG_RETURN_VALUE;
        event->return_value = ctx->ret;
        bpf_ringbuf_submit(event, 0);
    } else {
        count_file_missing_exit(cgroup_id, event_kind, update_scoped);
    }
    bpf_map_delete_elem(&APOLYSIS_PENDING_FILES, &pid_tgid);
    decrement_file_pending(cgroup_id, event_kind, update_scoped);
    end_scope_counter_update(cgroup_id, update_scoped);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int apolysis_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct apolysis_scope_config *config = scope_config();
    struct apolysis_kernel_event *event;
    unsigned long long event_cgroup_id;
    bool update_scoped;
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

    event = reserve_process_event(APOLYSIS_EVENT_FORK, &event_cgroup_id,
                                  &update_scoped);
    if (!event) {
        end_scope_counter_update(event_cgroup_id, update_scoped);
        return 0;
    }

    event->pid = ctx->child_pid;
    event->ppid = ctx->parent_pid;
    copy_action(event, "fork", 5);
    bpf_ringbuf_submit(event, 0);
    end_scope_counter_update(event_cgroup_id, update_scoped);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int apolysis_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct apolysis_kernel_event *event;
    struct apolysis_pending_exec *pending;
    const char *filename;
    unsigned long long event_cgroup_id;
    bool update_scoped;
    unsigned int pid;

    event = reserve_process_event(APOLYSIS_EVENT_EXEC, &event_cgroup_id,
                                  &update_scoped);
    if (!event) {
        end_scope_counter_update(event_cgroup_id, update_scoped);
        return 0;
    }

    filename = (const char *)ctx + (ctx->__data_loc_filename & 0xffff);
    pid = event->pid;
    pending = bpf_map_lookup_elem(&APOLYSIS_PENDING_EXECS, &pid);
    if (pending) {
        __builtin_memcpy(event->resource, pending->resource, sizeof(event->resource));
        __builtin_memcpy(event->payload, pending->payload, sizeof(event->payload));
        event->flags |= pending->flags;
        bpf_map_delete_elem(&APOLYSIS_PENDING_EXECS, &pid);
    } else {
        read_kernel_path(event, filename);
    }
    copy_action(event, "exec", 5);
    bpf_ringbuf_submit(event, 0);
    end_scope_counter_update(event_cgroup_id, update_scoped);
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
    struct apolysis_scope_config *config = scope_config();
    struct apolysis_kernel_event *event;
    unsigned long long pid_tgid;
    struct apolysis_pending_connect *pending_connect;
    struct apolysis_pending_file *pending_file;
    unsigned long long connect_cgroup_id;
    unsigned long long file_cgroup_id;
    unsigned int file_event_kind;
    unsigned long long event_cgroup_id;
    bool event_update_scoped;
    bool update_scoped;
    unsigned int pid;

    event = reserve_process_event(APOLYSIS_EVENT_EXIT, &event_cgroup_id,
                                  &event_update_scoped);
    pid_tgid = bpf_get_current_pid_tgid();
    pending_connect = bpf_map_lookup_elem(&APOLYSIS_PENDING_CONNECTS, &pid_tgid);
    if (pending_connect) {
        connect_cgroup_id = pending_connect->cgroup_id;
        update_scoped = begin_scope_counter_update(connect_cgroup_id);
        bpf_map_delete_elem(&APOLYSIS_PENDING_CONNECTS, &pid_tgid);
        decrement_connect_pending(connect_cgroup_id, update_scoped);
        count_connect_missing_exit(connect_cgroup_id, update_scoped);
        end_scope_counter_update(connect_cgroup_id, update_scoped);
    }
    pending_file = bpf_map_lookup_elem(&APOLYSIS_PENDING_FILES, &pid_tgid);
    if (pending_file) {
        file_cgroup_id = pending_file->cgroup_id;
        file_event_kind = pending_file->event_kind;
        update_scoped = begin_scope_counter_update(file_cgroup_id);
        bpf_map_delete_elem(&APOLYSIS_PENDING_FILES, &pid_tgid);
        decrement_file_pending(file_cgroup_id, file_event_kind, update_scoped);
        count_file_missing_exit(file_cgroup_id, file_event_kind, update_scoped);
        end_scope_counter_update(file_cgroup_id, update_scoped);
    }

    if (event) {
        event->pid = ctx->pid;
        bpf_probe_read_kernel(event->comm, sizeof(event->comm), ctx->comm);
        copy_action(event, "exit", 5);
        bpf_ringbuf_submit(event, 0);
    }
    end_scope_counter_update(event_cgroup_id, event_update_scoped);

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

    return capture_file_enter(open_event_kind(flags), APOLYSIS_FILE_SOURCE_OPENAT,
                              flags, (const char *)ctx->args[1], 0);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int apolysis_sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    return capture_file_exit(ctx, APOLYSIS_FILE_SOURCE_OPENAT,
                             APOLYSIS_EVENT_OPEN);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int apolysis_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long long flags = 0;

    bpf_probe_read_user(&flags, sizeof(flags), (const void *)ctx->args[2]);
    return capture_file_enter(open_event_kind(flags), APOLYSIS_FILE_SOURCE_OPENAT2,
                              flags, (const char *)ctx->args[1], 0);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int apolysis_sys_exit_openat2(struct trace_event_raw_sys_exit *ctx)
{
    return capture_file_exit(ctx, APOLYSIS_FILE_SOURCE_OPENAT2,
                             APOLYSIS_EVENT_OPEN);
}

SEC("tracepoint/syscalls/sys_enter_creat")
int apolysis_sys_enter_creat(struct trace_event_raw_sys_enter *ctx)
{
    return capture_file_enter(APOLYSIS_EVENT_CREATE, APOLYSIS_FILE_SOURCE_CREAT,
                              APOLYSIS_O_CREAT, (const char *)ctx->args[0], 0);
}

SEC("tracepoint/syscalls/sys_exit_creat")
int apolysis_sys_exit_creat(struct trace_event_raw_sys_exit *ctx)
{
    return capture_file_exit(ctx, APOLYSIS_FILE_SOURCE_CREAT,
                             APOLYSIS_EVENT_CREATE);
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int apolysis_sys_enter_truncate(struct trace_event_raw_sys_enter *ctx)
{
    return capture_file_enter(APOLYSIS_EVENT_TRUNCATE,
                              APOLYSIS_FILE_SOURCE_TRUNCATE, APOLYSIS_O_TRUNC,
                              (const char *)ctx->args[0], 0);
}

SEC("tracepoint/syscalls/sys_exit_truncate")
int apolysis_sys_exit_truncate(struct trace_event_raw_sys_exit *ctx)
{
    return capture_file_exit(ctx, APOLYSIS_FILE_SOURCE_TRUNCATE,
                             APOLYSIS_EVENT_TRUNCATE);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int apolysis_sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    return capture_file_enter(APOLYSIS_EVENT_UNLINK,
                              APOLYSIS_FILE_SOURCE_UNLINKAT, 0,
                              (const char *)ctx->args[1], 0);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int apolysis_sys_exit_unlinkat(struct trace_event_raw_sys_exit *ctx)
{
    return capture_file_exit(ctx, APOLYSIS_FILE_SOURCE_UNLINKAT,
                             APOLYSIS_EVENT_UNLINK);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int apolysis_sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    return capture_file_enter(APOLYSIS_EVENT_RENAME,
                              APOLYSIS_FILE_SOURCE_RENAMEAT2, 0,
                              (const char *)ctx->args[1],
                              (const char *)ctx->args[3]);
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int apolysis_sys_exit_renameat2(struct trace_event_raw_sys_exit *ctx)
{
    return capture_file_exit(ctx, APOLYSIS_FILE_SOURCE_RENAMEAT2,
                             APOLYSIS_EVENT_RENAME);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int apolysis_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct apolysis_pending_connect *pending;
    struct apolysis_pending_connect *stale;
    unsigned long long pid_tgid;
    unsigned long long cgroup_id;
    unsigned long long stale_cgroup_id = 0;
    bool update_scoped;
    unsigned long long length;
    unsigned int scratch_key = 0;
    unsigned short family = 0;
    bool replaces_stale_entry;

    if (!current_is_in_scope())
        return 0;
    cgroup_id = bpf_get_current_cgroup_id();
    update_scoped = begin_scope_counter_update(cgroup_id);
    if (multi_cgroup_scope() && !update_scoped) {
        if (cgroup_scope_state(cgroup_id) == APOLYSIS_CGROUP_ACTIVE)
            count_map_pressure();
        return 0;
    }
    pending = bpf_map_lookup_elem(&APOLYSIS_CONNECT_SCRATCH, &scratch_key);
    if (!pending) {
        end_scope_counter_update(cgroup_id, update_scoped);
        count_map_pressure();
        return 0;
    }

    __builtin_memset(pending, 0, sizeof(*pending));
    pending->cgroup_id = cgroup_id;
    length = ctx->args[2];
    if (length > sizeof(pending->payload)) {
        length = sizeof(pending->payload);
        pending->flags |= APOLYSIS_FLAG_PAYLOAD_TRUNCATED;
    }
    if (bpf_probe_read_user(pending->payload, length, (const void *)ctx->args[1]) == 0 &&
        length >= sizeof(family)) {
        __builtin_memcpy(&family, pending->payload, sizeof(family));
        if ((family == APOLYSIS_AF_INET && length >= 8) ||
            (family == APOLYSIS_AF_INET6 && length >= 24) ||
            (family != APOLYSIS_AF_INET && family != APOLYSIS_AF_INET6 && length >= 4))
            pending->flags |= APOLYSIS_FLAG_PAYLOAD_SOCKADDR;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    stale = bpf_map_lookup_elem(&APOLYSIS_PENDING_CONNECTS, &pid_tgid);
    replaces_stale_entry = stale != 0;
    if (stale)
        stale_cgroup_id = stale->cgroup_id;
    if (bpf_map_update_elem(&APOLYSIS_PENDING_CONNECTS, &pid_tgid, pending, BPF_ANY)) {
        if (replaces_stale_entry) {
            bpf_map_delete_elem(&APOLYSIS_PENDING_CONNECTS, &pid_tgid);
            account_stale_connect(stale_cgroup_id);
        }
        end_scope_counter_update(cgroup_id, update_scoped);
        count_map_pressure();
        return 0;
    }
    if (replaces_stale_entry)
        account_stale_connect(stale_cgroup_id);
    increment_connect_pending(cgroup_id, update_scoped);
    end_scope_counter_update(cgroup_id, update_scoped);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int apolysis_sys_exit_connect(struct trace_event_raw_sys_exit *ctx)
{
    struct apolysis_pending_connect *pending;
    struct apolysis_kernel_event *event;
    unsigned long long pid_tgid;
    unsigned long long cgroup_id;
    unsigned long long current_cgroup_id;
    bool update_scoped;

    pid_tgid = bpf_get_current_pid_tgid();
    pending = bpf_map_lookup_elem(&APOLYSIS_PENDING_CONNECTS, &pid_tgid);
    if (!pending) {
        if (multi_cgroup_scope()) {
            current_cgroup_id = bpf_get_current_cgroup_id();
            update_scoped = begin_scope_counter_update(current_cgroup_id);
            if (update_scoped) {
                count_connect_missing_entry(current_cgroup_id, update_scoped);
                end_scope_counter_update(current_cgroup_id, update_scoped);
            }
        } else if (current_is_in_scope()) {
            current_cgroup_id = bpf_get_current_cgroup_id();
            count_connect_missing_entry(current_cgroup_id, 0);
        }
        return 0;
    }
    cgroup_id = pending->cgroup_id;
    update_scoped = begin_scope_counter_update(cgroup_id);
    if (!pair_is_in_scope(cgroup_id)) {
        bpf_map_delete_elem(&APOLYSIS_PENDING_CONNECTS, &pid_tgid);
        decrement_connect_pending(cgroup_id, update_scoped);
        count_connect_missing_exit(cgroup_id, update_scoped);
        end_scope_counter_update(cgroup_id, update_scoped);
        return 0;
    }

    /*
     * pair_is_in_scope made the scope decision while update_scoped
     * holds the per-cgroup drain barrier. Do not re-read the ACTIVE/DRAINING
     * state here: userspace may switch it after that decision and waits for
     * this handler before snapshotting the counters.
     */
    event = reserve_event_unchecked(APOLYSIS_EVENT_CONNECT);
    if (event) {
        __builtin_memcpy(event->payload, pending->payload, sizeof(event->payload));
        event->flags |= pending->flags | APOLYSIS_FLAG_RETURN_VALUE;
        event->return_value = ctx->ret;
        copy_action(event, "connect", 8);
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&APOLYSIS_PENDING_CONNECTS, &pid_tgid);
    decrement_connect_pending(cgroup_id, update_scoped);
    end_scope_counter_update(cgroup_id, update_scoped);
    return 0;
}
