// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// The maximum size of environment buffer the program can scan. 
// Anything that exceeds this is a blind spot.
#define MAX_ENV_SIZE 512

// The maximum possible size of a request ID.
#define REQUEST_ID_MAX 64

struct env_buf
{
    char buf[MAX_ENV_SIZE];
};
// We define a per cpu map to store the env buffer for scanning 
// so that we do not consume the 512 byte BPF stack size limit.
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct env_buf);
} env_scratch SEC(".maps");

// format of the event that would be emitted to the ring buffer.
struct event
{
    u32 pid;
    u32 ppid;
    char comm[16];
    char parent_comm[16];
    char filename[128];
    char request_id[REQUEST_ID_MAX];
};

// definition of ring buffer.
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct event *e;
    struct env_buf *scratch;
    unsigned long env_start, env_end;
    u32 pid, ppid;
    u32 zero = 0;
    u32 env_size;
    int found_off = -1;

    // load the env buffer scratch map into the programs memory.
    // use the pointer to traverse through the env buffer.
    scratch = bpf_map_lookup_elem(&env_scratch, &zero);
    if (!scratch)
        return 0;

    // get a handle to the current task struct
    task = bpf_get_current_task_btf();
    if (!task)
        return 0;

    // fetch the memory address space
    mm = BPF_CORE_READ(task, mm);
    // BPF_CORE_READ is used because the BPF verifier does not allow direct
    // pointer dereference of kernel pointers. It also handles struct field
    // offset differences across kernel versions via CO-RE relocation.
    if (!mm)
        return 0;

    env_start = BPF_CORE_READ(mm, env_start);
    env_end = BPF_CORE_READ(mm, env_end);



    if (!env_start || !env_end || env_end <= env_start)
        return 0;

    // if the size of the env_size exceeds that of the maximum allowed size,
    // limit at the predefined value to stay within the loop bound.
    env_size = env_end - env_start;
    if (env_size > MAX_ENV_SIZE)
        env_size = MAX_ENV_SIZE;

    // read the environment variable buffer from the user space to the scratch buffer
    long ret = bpf_probe_read_user(scratch->buf, env_size, (void *)env_start);
    if (ret < 0)
        return 0;

    // Search for the environment variable K8S_REQUEST_ID
    #pragma unroll
    for (int i = 0; i < MAX_ENV_SIZE - 15; i++)
    {
        if (scratch->buf[i] == 'K' &&
            scratch->buf[i + 1] == '8' &&
            scratch->buf[i + 2] == 'S' &&
            scratch->buf[i + 3] == '_' &&
            scratch->buf[i + 4] == 'R' &&
            scratch->buf[i + 5] == 'E' &&
            scratch->buf[i + 6] == 'Q' &&
            scratch->buf[i + 7] == 'U' &&
            scratch->buf[i + 8] == 'E' &&
            scratch->buf[i + 9] == 'S' &&
            scratch->buf[i + 10] == 'T' &&
            scratch->buf[i + 11] == '_' &&
            scratch->buf[i + 12] == 'I' &&
            scratch->buf[i + 13] == 'D' &&
            scratch->buf[i + 14] == '=')
        {
            found_off = i + 15;
            break;
        }
    }

    if (found_off < 0 || found_off >= MAX_ENV_SIZE)
        return 0;

    // Reserve ringbuffer memory to write into it directly
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->pid = pid;
    e->ppid = ppid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    BPF_CORE_READ_STR_INTO(&e->parent_comm, task, real_parent, comm);

    u32 fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename),
                       (void *)ctx + fname_off);

    // Write the request ID into the ring buffer event
    if (found_off + REQUEST_ID_MAX <= MAX_ENV_SIZE)
    {
        #pragma unroll
        for (int j = 0; j < REQUEST_ID_MAX; j++)
        {
            char c = scratch->buf[(found_off + j) & (MAX_ENV_SIZE - 1)];
            if (c == '\0')
                break;
            e->request_id[j & (REQUEST_ID_MAX - 1)] = c;
        }
    }

    // Emit the event
    bpf_ringbuf_submit(e, 0);
    return 0;
}