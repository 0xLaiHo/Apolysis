/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef APOLYSIS_OBSERVER_H
#define APOLYSIS_OBSERVER_H

#define APOLYSIS_COMM_LEN 16
#define APOLYSIS_RESOURCE_LEN 256
#define APOLYSIS_ACTION_LEN 32
#define APOLYSIS_PAYLOAD_LEN 256
#define APOLYSIS_KERNEL_ABI_VERSION 3
#define APOLYSIS_KERNEL_EVENT_RECORD_LEN 656

enum apolysis_kernel_event_kind {
    APOLYSIS_EVENT_EXEC = 1,
    APOLYSIS_EVENT_OPEN = 2,
    APOLYSIS_EVENT_CREATE = 3,
    APOLYSIS_EVENT_TRUNCATE = 4,
    APOLYSIS_EVENT_UNLINK = 5,
    APOLYSIS_EVENT_RENAME = 6,
    APOLYSIS_EVENT_CONNECT = 7,
    APOLYSIS_EVENT_EXIT = 8,
    APOLYSIS_EVENT_FORK = 9,
};

enum apolysis_event_flags {
    APOLYSIS_FLAG_RESOURCE_TRUNCATED = 1 << 0,
    APOLYSIS_FLAG_PAYLOAD_TRUNCATED = 1 << 1,
    APOLYSIS_FLAG_PAYLOAD_SOCKADDR = 1 << 2,
    APOLYSIS_FLAG_ARGV_TRUNCATED = 1 << 3,
    APOLYSIS_FLAG_RETURN_VALUE = 1 << 4,
};

enum apolysis_scope_mode {
    APOLYSIS_SCOPE_CGROUP = 1,
    APOLYSIS_SCOPE_PID_TREE = 2,
    APOLYSIS_SCOPE_MULTI_CGROUP = 3,
};

enum apolysis_cgroup_scope_state {
    APOLYSIS_CGROUP_ACTIVE = 1,
    APOLYSIS_CGROUP_DRAINING = 2,
};

struct apolysis_scope_config {
    unsigned long long cgroup_id;
    unsigned int root_pid;
    unsigned int mode;
};

struct apolysis_operation_pair_counters {
    unsigned long long missing_entries;
    unsigned long long missing_exits;
    unsigned long long pending;
};

struct apolysis_file_operation_counters {
    struct apolysis_operation_pair_counters open;
    struct apolysis_operation_pair_counters create;
    struct apolysis_operation_pair_counters truncate;
    struct apolysis_operation_pair_counters unlink;
    struct apolysis_operation_pair_counters rename;
};

struct apolysis_observer_counters {
    unsigned long long reserve_failures;
    unsigned long long map_pressure;
    unsigned long long connect_missing_entries;
    unsigned long long connect_missing_exits;
    unsigned long long connect_pending;
    struct apolysis_file_operation_counters file_operations;
};

struct apolysis_network_connect_counters {
    unsigned long long missing_entries;
    unsigned long long missing_exits;
    unsigned long long pending;
};

_Static_assert(sizeof(struct apolysis_network_connect_counters) == 24,
               "apolysis network connect counter ABI size mismatch");
_Static_assert(sizeof(struct apolysis_operation_pair_counters) == 24,
               "apolysis operation pair counter ABI size mismatch");
_Static_assert(sizeof(struct apolysis_file_operation_counters) == 120,
               "apolysis file operation counter ABI size mismatch");
_Static_assert(sizeof(struct apolysis_observer_counters) == 160,
               "apolysis observer counter ABI size mismatch");

/*
 * ABI shared between the observer eBPF program and the Rust userspace loader.
 * Keep fixed-size fields explicit so CO-RE object compatibility and Rust mirror
 * tests can be added before this becomes a stable external format.
 */
struct apolysis_kernel_event {
    unsigned int abi_version;
    unsigned int record_size;
    unsigned long long timestamp_ns;
    unsigned long long cgroup_id;
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    unsigned int gid;
    unsigned int event_kind;
    unsigned int flags;
    long long return_value;
    unsigned long long scope_generation;
    unsigned long long process_generation;
    unsigned long long process_start_time_ns;
    unsigned long long parent_process_generation;
    unsigned int exec_generation;
    unsigned int parent_exec_generation;
    char comm[APOLYSIS_COMM_LEN];
    char resource[APOLYSIS_RESOURCE_LEN];
    char action[APOLYSIS_ACTION_LEN];
    char payload[APOLYSIS_PAYLOAD_LEN];
};

_Static_assert(sizeof(struct apolysis_kernel_event) == APOLYSIS_KERNEL_EVENT_RECORD_LEN,
               "apolysis kernel event ABI size mismatch");

#endif /* APOLYSIS_OBSERVER_H */
