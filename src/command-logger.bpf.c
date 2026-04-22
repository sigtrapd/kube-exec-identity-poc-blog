// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ENV_VARS 40
#define REQUEST_ID_MAX 64
#define MAX_ARGS_SIZE 256

struct request_data {
    char request_id[REQUEST_ID_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct request_data);
} task_storage_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct request_data);
} staging_map SEC(".maps");

struct event {
    u32  pid;
    u32  ppid;
    char comm[16];
    char parent_comm[16];
    char filename[128];
    char args[MAX_ARGS_SIZE];
    char request_id[REQUEST_ID_MAX];
    u32  storage_written;
    u32  from_parent;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

// ── Hook 1 — sys_enter_execve ─────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_execve")
int hook1_read_identity(struct trace_event_raw_sys_enter *ctx)
{
    const char **envp = (const char **)ctx->args[2];
    if (!envp)
        return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    for (int i = 0; i < MAX_ENV_VARS; i++) {
        const char *entry = NULL;
        long ret = bpf_probe_read_user(&entry, sizeof(entry), &envp[i]);
        if (ret < 0 || !entry)
            break;

        char var[REQUEST_ID_MAX + 16] = {};
        ret = bpf_probe_read_user_str(var, sizeof(var), entry);
        if (ret < 0)
            continue;

        if (var[0]  == 'K' && var[1]  == '8' && var[2]  == 'S' &&
            var[3]  == '_' && var[4]  == 'R' && var[5]  == 'E' &&
            var[6]  == 'Q' && var[7]  == 'U' && var[8]  == 'E' &&
            var[9]  == 'S' && var[10] == 'T' && var[11] == '_' &&
            var[12] == 'I' && var[13] == 'D' && var[14] == '=') {

            // Write to task_storage
            struct request_data *rd = bpf_task_storage_get(
                &task_storage_map, task, NULL,
                BPF_LOCAL_STORAGE_GET_F_CREATE);
            if (rd) {
                bpf_probe_read_kernel_str(rd->request_id,
                    sizeof(rd->request_id), var + 15);

                // Also write to staging map for hook3 to emit session event
                struct request_data staging = {};
                bpf_probe_read_kernel_str(staging.request_id,
                    sizeof(staging.request_id), var + 15);
                bpf_map_update_elem(&staging_map, &pid, &staging, BPF_ANY);

                bpf_printk("hook1: pid:%d requestId:%s\n", pid, rd->request_id);
            }
            break;
        }
    }

    return 0;
}

// ── Hook 2 — lsm/bprm_check_security ─────────────────────────────────────
SEC("lsm/bprm_check_security")
int BPF_PROG(hook2_propagate_identity, struct linux_binprm *bprm,
             bool called_from_execve)
{
    struct task_struct *task;
    struct task_struct *parent;
    struct request_data *rd;
    struct request_data staging = {};
    u32 pid, ppid;

    task = bpf_get_current_task_btf();
    if (!task)
        return 0;

    pid  = bpf_get_current_pid_tgid() >> 32;
    ppid = BPF_CORE_READ(task, real_parent, tgid);

    parent = bpf_task_from_pid(ppid);
    if (!parent)
        return 0;

    rd = bpf_task_storage_get(&task_storage_map, parent, NULL, 0);
    bpf_task_release(parent);

    if (!rd)
        return 0;

    bpf_printk("hook2: pid:%d ppid:%d propagating requestId\n", pid, ppid);

    #pragma unroll
    for (int j = 0; j < REQUEST_ID_MAX; j++) {
        staging.request_id[j & (REQUEST_ID_MAX - 1)] =
            rd->request_id[j & (REQUEST_ID_MAX - 1)];
    }

    bpf_map_update_elem(&staging_map, &pid, &staging, BPF_ANY);

    return 0;
}

// ── Hook 3 — sched_process_exec ──────────────────────────────────────────
SEC("tp/sched/sched_process_exec")
int hook3_emit_event(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct request_data *rd;
    struct event *e;
    u32 pid, ppid;

    pid = bpf_get_current_pid_tgid() >> 32;

    rd = bpf_map_lookup_elem(&staging_map, &pid);
    if (!rd)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&staging_map, &pid);
        return 0;
    }

    task = bpf_get_current_task_btf();
    if (!task) {
        bpf_ringbuf_discard(e, 0);
        bpf_map_delete_elem(&staging_map, &pid);
        return 0;
    }

    ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->pid             = pid;
    e->ppid            = ppid;
    e->storage_written = 0;
    e->from_parent     = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    BPF_CORE_READ_STR_INTO(&e->parent_comm, task, real_parent, comm);

    u32 fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename),
                        (void *)ctx + fname_off);

    mm = BPF_CORE_READ(task, mm);
    if (mm) {
        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        unsigned long arg_end   = BPF_CORE_READ(mm, arg_end);
        if (arg_start && arg_end && arg_end > arg_start) {
            char skip_buf[128] = {};
            long skip = bpf_probe_read_user_str(skip_buf, sizeof(skip_buf),
                                                 (void *)arg_start);
            if (skip > 0 && arg_start + skip < arg_end) {
                arg_start += skip;
                long arg_size = arg_end - arg_start;
                if (arg_size > MAX_ARGS_SIZE)
                    arg_size = MAX_ARGS_SIZE;
                bpf_probe_read_user(&e->args,
                                     arg_size & (MAX_ARGS_SIZE - 1),
                                     (void *)arg_start);
            }
        }
    }

    #pragma unroll
    for (int j = 0; j < REQUEST_ID_MAX; j++) {
        e->request_id[j & (REQUEST_ID_MAX - 1)] =
            rd->request_id[j & (REQUEST_ID_MAX - 1)];
    }

    bpf_map_delete_elem(&staging_map, &pid);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
