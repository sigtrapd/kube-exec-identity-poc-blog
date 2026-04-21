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

## What this iteration is not

- It does not persist anything. Output is stdout only.
- It trusts the variable at face value. Any process that chooses to export
  `K8S_REQUEST_ID` will be recorded as if it were legitimate.
- The 512-byte env scan is a hard blind spot. Anything past that is missed.

Each of these is on the list. Later iterations earn the right to solve them.
