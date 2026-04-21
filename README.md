# kubernetes-exec-identity

The API server knows who opened a `kubectl exec` session. The kernel knows what the
session ran. Nothing in the platform ties the two together. This repo is the
iterative work of closing that gap, one small, honest step at a time.

The reasoning lives on the blog:

1. [The Kubernetes Exec Identity Gap: Kubernetes Cannot Tell You Who Ran That Command](https://blog.sigtrapd.dev/posts/k8s-exec-identity-gap/) — names the gap, sketches the two fixes.
2. [Exploring the Kubernetes Exec Identity Gap: Why the Obvious Fixes Fail and What Actually Works](https://blog.sigtrapd.dev/posts/exploring-the-exec-identity-gap/) — why the PID cannot exist when audit needs it, and why eBPF is the remaining credible path.
3. [Bridging the Kubernetes Exec Identity Gap: One Hook Was Never Enough](https://blog.sigtrapd.dev/posts/bridging-k8s-exec-identity-gap/) - the build log. Each iteration in this repo corresponds to a step in that post.

## Iteration 1

The smallest thing that can possibly work: observe every exec on the node, and
if the process carries a `K8S_REQUEST_ID` environment variable, print it next
to the usual process fields.

- A tracepoint on `sched/sched_process_exec` fires on every `execve` in the system.
- For each exec, the program reads the target's env block via
  `BPF_CORE_READ(task, mm, env_start/env_end)` into a per-CPU scratch buffer, and
  scans up to 512 bytes for `K8S_REQUEST_ID=<value>`.
- If present, the value is captured and emitted alongside `pid`, `ppid`, `comm`,
  `parent_comm`, and `filename` on a `BPF_MAP_TYPE_RINGBUF`.
- A Go reader pulls events off the ring buffer and prints one row per exec.

This iteration does not set `K8S_REQUEST_ID`. It only assumes something upstream
(an admission mutation, a wrapped exec, an operator simulating one) has put the
API server's audit / request UID into the exec'd process's environment. Given
that assumption, the kernel can now name who asked for the command.

## Iteration 2

Write the request ID into task-local storage and read it back. Just enough to
confirm the round-trip works.

- Add a `BPF_MAP_TYPE_TASK_STORAGE` map (`task_storage_map`) keyed by the
  `task_struct` and holding `struct request_data { char request_id[64]; }`.
  The map is declared `BPF_F_NO_PREALLOC` because task storage is created on
  demand, one slot per task that actually needs it.
- After finding `K8S_REQUEST_ID=<value>` in the env scan, call
  `bpf_task_storage_get(..., BPF_LOCAL_STORAGE_GET_F_CREATE)` to allocate or
  fetch the slot for the current task, and copy the value in with
  `bpf_probe_read_kernel_str`.
- The emitted event gains a `storage_written` flag and now reads `request_id`
  back from task storage instead of directly from the scratch buffer. The
  reader surfaces this as a new `STORED` column. The round-trip is deliberately
  redundant — it is the cheapest possible proof that writing to and reading
  from task storage actually works end-to-end.

## Iteration 3

Make the parent's task storage the source of truth. Env is consulted only at
the root of a session — for everything downstream, the kernel's own record of
the ancestor wins.

- On every `sched_process_exec`, look up `task->real_parent` in
  `task_storage_map`. If the parent carries a non-empty `request_id`, copy it
  straight into the child's slot and skip the env scan entirely.
- The env scan only runs when the parent has nothing. In practice that is the
  session root — the first process the mutating webhook injected
  `K8S_REQUEST_ID` into.
- Once the root is stored, every descendant — shells, pipelines, whatever a
  user runs — inherits the identity by ancestry. A child that sets
  `K8S_REQUEST_ID=<anything>` in its own env is ignored, because the lookup
  against the parent short-circuits before the env block is ever read.
- The event gains a `from_parent` flag and the reader gains a `PARENT_SRC`
  column (`1` = inherited from the parent's task storage, `0` = scanned from
  env at the root).

One implementation detail worth the line: `task->real_parent` is read as a
direct field access rather than through `BPF_CORE_READ`. `BPF_CORE_READ`
returns a scalar, and `bpf_task_storage_get` refuses anything that is not a
"trusted" pointer. The program does not load if you get this wrong.

The env scan also got some room to breathe. `MAX_ENV_SIZE` moves from 512 to
2048, which covers almost every real-world process environment we saw. To
keep the verifier happy at the larger bound, the 15-byte unrolled `K8S_...`
compare was rewritten as a rolling state machine that advances one character
at a time and resyncs fast on `K`. Same result, four times the reach, no
verifier fight.

## Layout

- `src/command-logger.bpf.c` — the eBPF program.
- `src/handler.go` — the user-space ring buffer reader.
- `src/Makefile` — `clang` invocation that produces `command-logger.bpf.o`.

## Build and run

Needs a Linux node with BTF, ring buffers, and `bpf_get_current_task_btf`
(roughly 5.11+). Needs `clang` and the libbpf headers under `/usr/include/bpf`.

Generate `vmlinux.h` once, build, and run:

```bash
cd src
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
make
sudo go run .
```

Then, from another terminal, exec into a pod scheduled on the same node and set
the variable:

```bash
kubectl exec -it some-pod -- env K8S_REQUEST_ID=demo-001 /bin/sh
```

Any command you run inside that shell shows up in the reader's output with
`demo-001` in the `REQUEST_ID` column.

## What still doesn't work

- No persistence beyond the reader's stdout. Nothing is written anywhere
  durable yet.
- The 2048-byte env scan is still a bounded window. Environments larger than
  that at the session root are a blind spot.
- Env at the root is still the one point of trust. The whole chain holds
  only if the mutating webhook is what put `K8S_REQUEST_ID` there; anything
  else that injects the variable on a root-level exec gets believed once, and
  then inherited by every child.

Each of these is on the list. Later iterations earn the right to solve them.
