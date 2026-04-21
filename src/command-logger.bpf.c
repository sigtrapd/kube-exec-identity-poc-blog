// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Max bytes copied from the process env block into scratch for scanning.
// Linux environ can be much larger (ARG_MAX); this is our deliberate cap.
#define MAX_ENV_SIZE 2048

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


struct request_data {
    char request_id[REQUEST_ID_MAX];
};
// Task storage is a custom bpf map whose lifecycle is tracked 
// alongside that of the corresponding process itself.
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct request_data);
} task_storage_map SEC(".maps");


// format of the event that would be emitted to the ring buffer.
struct event
{
    u32 pid;
    u32 ppid;
    u32 storage_written;
    u32 from_parent;
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
    struct task_struct *parent;
    struct mm_struct *mm;
    struct event *e;
    struct env_buf *scratch;
    struct request_data *rd = NULL;
    struct request_data *prd;
    unsigned long env_start, env_end;
    u32 pid, ppid;
    u32 zero = 0;
    u32 env_size;
    u32 storage_written = 0;
    u32 from_parent = 0;
    int found_off = -1;
    char parent_id0;

    // load the env buffer scratch map into the programs memory.
    // use the pointer to traverse through the env buffer.
    scratch = bpf_map_lookup_elem(&env_scratch, &zero);
    if (!scratch)
        return 0;

    // get a handle to the current task struct
    task = bpf_get_current_task_btf();
    if (!task)
        return 0;

    /* Direct field access keeps the pointer "trusted" for the verifier;
     * BPF_CORE_READ would turn it into a scalar and bpf_task_storage_get
     * rejects that. */
    parent = task->real_parent;
    if (parent) {
        prd = bpf_task_storage_get(&task_storage_map, parent, NULL, 0);
        if (prd &&
            bpf_probe_read_kernel(&parent_id0, 1, prd->request_id) == 0 &&
            parent_id0) {
            rd = bpf_task_storage_get(&task_storage_map, task, NULL,
                          BPF_LOCAL_STORAGE_GET_F_CREATE);
            if (rd) {
                bpf_probe_read_kernel_str(rd->request_id,
                              sizeof(rd->request_id),
                              prd->request_id);
                storage_written = 1;
                from_parent = 1;
                /* Parent already carries the identity: skip the env scan. */
                goto emit;
            }
        }
    }

    scratch = bpf_map_lookup_elem(&env_scratch, &zero);
    if (!scratch)
        goto emit;

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

    {
        const char needle[] = "K8S_REQUEST_ID=";
        u32 state = 0;

#pragma clang loop unroll(disable)
        for (int i = 0; i < MAX_ENV_SIZE - 15; i++) {
            unsigned char c = scratch->buf[i];

            if (c == (unsigned char)needle[state]) {
                state++;
                if (state == 15) {
                    found_off = i + 1;
                    break;
                }
            } else {
                state = (c == 'K') ? 1 : 0;
            }
        }
    }

    if (found_off >= 0 && found_off < MAX_ENV_SIZE) {
        if (!rd)
            rd = bpf_task_storage_get(&task_storage_map, task, NULL,
                          BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (rd) {
            bpf_probe_read_kernel_str(rd->request_id,
                           sizeof(rd->request_id),
                           scratch->buf + found_off);
            storage_written = 1;
            from_parent = 0;
        }
    }

emit:
    if (!storage_written || !rd)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->pid = pid;
    e->ppid = ppid;
    e->storage_written = storage_written;
    e->from_parent = from_parent;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    BPF_CORE_READ_STR_INTO(&e->parent_comm, task, real_parent, comm);

    u32 fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename),
                       (void *)ctx + fname_off);

    // Read the request ID from the task storage. 
    // Though this may feel unnecessary, the goal here is to verify 
    // if we can write to and read from the task storage.
    bpf_probe_read_kernel_str(e->request_id,
                            sizeof(e->request_id), rd->request_id);

    // Emit the event
    bpf_ringbuf_submit(e, 0);
    return 0;
}
