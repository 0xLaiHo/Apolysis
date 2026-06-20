// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define APOLYSIS_EPERM 1

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} apolysis_bpf_lsm_target_tgid SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(apolysis_bpf_lsm_file_open, struct file *file, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 key = 0;
    __u32 *target_tgid;

    if (ret)
        return ret;

    target_tgid = bpf_map_lookup_elem(&apolysis_bpf_lsm_target_tgid, &key);
    if (!target_tgid || *target_tgid == 0 || *target_tgid != tgid)
        return 0;

    return -APOLYSIS_EPERM;
}
