// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define REQUEST_ID_MAX 64
#define MAX_ARGS_SIZE  256
#define MAX_ENV_VARS   64

struct request_data {
    char request_id[REQUEST_ID_MAX];
};

// Task storage: per-task slot that survives for the task's lifetime and is
// auto-freed when the task exits. Keyed implicitly by the task_struct pointer.
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct request_data);
} task_storage_map SEC(".maps");

// Event emitted to user space on every successful exec we can attribute.
struct event {
    u32  pid;
    u32  ppid;
    u32  storage_written;   // always 1 today, kept for future "unattributed" events
    u32  from_parent;       // 1 if the request_id came via parent inheritance
    char comm[16];
    char parent_comm[16];
    char filename[128];
    char request_id[REQUEST_ID_MAX];
    char args[MAX_ARGS_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// ── Hook 1 ─ sys_enter_execve ────────────────────────────────────────────
// Iterate the user-space envp[] of the exec being attempted and, if we find
// K8S_REQUEST_ID=<value>, stash <value> into the current task's storage.
// This runs BEFORE the exec commits, so we're persisting identity the
// running task is about to carry into its new image.
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    const char **envp = (const char **)ctx->args[2];
    if (!envp)
        return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return 0;

    // Each env entry lives on the stack briefly; stays well under the 512 B
    // BPF stack limit (prefix 15 + REQUEST_ID_MAX 64 + some slack).
    for (int i = 0; i < MAX_ENV_VARS; i++) {
        const char *entry = NULL;
        if (bpf_probe_read_user(&entry, sizeof(entry), &envp[i]) < 0)
            break;
        if (!entry)
            break; // NULL terminator of envp[]

        char var[REQUEST_ID_MAX + 16] = {};
        long n = bpf_probe_read_user_str(var, sizeof(var), entry);
        if (n < 0)
            continue;

        if (var[0]  == 'K' && var[1]  == '8' && var[2]  == 'S' &&
            var[3]  == '_' && var[4]  == 'R' && var[5]  == 'E' &&
            var[6]  == 'Q' && var[7]  == 'U' && var[8]  == 'E' &&
            var[9]  == 'S' && var[10] == 'T' && var[11] == '_' &&
            var[12] == 'I' && var[13] == 'D' && var[14] == '=') {

            struct request_data *rd = bpf_task_storage_get(
                &task_storage_map, task, NULL,
                BPF_LOCAL_STORAGE_GET_F_CREATE);
            if (rd) {
                bpf_probe_read_kernel_str(rd->request_id,
                    sizeof(rd->request_id), var + 15);
            }
            break;
        }
    }
    return 0;
}

// ── Hook 2 ─ sched_process_exec ──────────────────────────────────────────
// Fires only on a successful exec. Preference order for request_id:
//   1. Current task's storage (written by hook1 from envp).
//   2. Parent task's storage (inherited).
// If neither is present, we don't emit — the event has no identity to carry.
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    struct task_struct *parent;
    struct mm_struct *mm;
    struct event *e;
    struct request_data *rd;
    struct request_data *prd;
    u32 pid, ppid;
    u32 from_parent = 0;
    char id0;

    task = bpf_get_current_task_btf();
    if (!task)
        return 0;

    // 1. Parent takes precedence: if the parent has a request_id, use it
    //    and overwrite anything hook1 may have put into this task's storage.
    parent = task->real_parent;
    if (parent) {
        prd = bpf_task_storage_get(&task_storage_map, parent, NULL, 0);
        if (prd &&
            bpf_probe_read_kernel(&id0, 1, prd->request_id) == 0 &&
            id0) {
            rd = bpf_task_storage_get(&task_storage_map, task, NULL,
                                      BPF_LOCAL_STORAGE_GET_F_CREATE);
            if (!rd)
                return 0;
            bpf_probe_read_kernel_str(rd->request_id,
                                      sizeof(rd->request_id),
                                      prd->request_id);
            from_parent = 1;
            goto emit;
        }
    }

    // 2. No parent identity: fall back to whatever hook1 captured from envp.
    rd = bpf_task_storage_get(&task_storage_map, task, NULL, 0);
    if (!rd ||
        bpf_probe_read_kernel(&id0, 1, rd->request_id) != 0 ||
        !id0)
        return 0;

emit:

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    pid  = bpf_get_current_pid_tgid() >> 32;
    ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->pid             = pid;
    e->ppid            = ppid;
    e->storage_written = 1;
    e->from_parent     = from_parent;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    BPF_CORE_READ_STR_INTO(&e->parent_comm, task, real_parent, comm);

    u32 fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename),
                       (void *)ctx + fname_off);

    bpf_probe_read_kernel_str(e->request_id,
                              sizeof(e->request_id), rd->request_id);

    // Ship the raw argv region (NUL-separated, starts with argv[0]).
    __builtin_memset(e->args, 0, sizeof(e->args));
    mm = task->mm;
    if (mm) {
        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        unsigned long arg_end   = BPF_CORE_READ(mm, arg_end);
        if (arg_start && arg_end && arg_end > arg_start) {
            long arg_size = arg_end - arg_start;
            if (arg_size > MAX_ARGS_SIZE)
                arg_size = MAX_ARGS_SIZE;
            bpf_probe_read_user(e->args,
                                arg_size & (MAX_ARGS_SIZE - 1),
                                (void *)arg_start);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}