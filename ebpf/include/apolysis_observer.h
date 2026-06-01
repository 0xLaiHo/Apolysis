/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef APOLYSIS_OBSERVER_H
#define APOLYSIS_OBSERVER_H

#define APOLYSIS_COMM_LEN 16
#define APOLYSIS_RESOURCE_LEN 256
#define APOLYSIS_ACTION_LEN 32
#define APOLYSIS_PAYLOAD_LEN 256

enum apolysis_kernel_event_kind {
    APOLYSIS_EVENT_EXEC = 1,
    APOLYSIS_EVENT_OPEN = 2,
    APOLYSIS_EVENT_CREATE = 3,
    APOLYSIS_EVENT_TRUNCATE = 4,
    APOLYSIS_EVENT_UNLINK = 5,
    APOLYSIS_EVENT_RENAME = 6,
    APOLYSIS_EVENT_CONNECT = 7,
};

/*
 * ABI shared between the observer eBPF program and the Rust userspace loader.
 * Keep fixed-size fields explicit so CO-RE object compatibility and Rust mirror
 * tests can be added before this becomes a stable external format.
 */
struct apolysis_kernel_event {
    unsigned long long timestamp_ns;
    unsigned long long cgroup_id;
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    unsigned int gid;
    unsigned int event_kind;
    char comm[APOLYSIS_COMM_LEN];
    char resource[APOLYSIS_RESOURCE_LEN];
    char action[APOLYSIS_ACTION_LEN];
    char payload[APOLYSIS_PAYLOAD_LEN];
};

#endif /* APOLYSIS_OBSERVER_H */
