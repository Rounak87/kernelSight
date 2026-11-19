#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/*
 * Process metrics tracked per-PID in kernel space.
 * Aggregated by BCC and consumed by collector.py in user space.
 */
struct proc_metrics {
    u64 total_stall_ns;
    u64 stall_count;
    u64 involuntary_switches;
    u64 voluntary_switches;
    u64 major_faults;
    u64 minor_faults;
    u64 total_syscall_ns;
    u64 syscall_count;
    u64 total_lock_wait_ns;
    u64 lock_wait_count;
    char comm[16];
};

BPF_HASH(metrics, u32, struct proc_metrics);
BPF_HASH(sched_start, u32, u64);
BPF_HASH(syscall_start, u64, u64);
BPF_HASH(lock_start, u64, u64);

static inline struct proc_metrics *get_metrics(u32 pid) {
    struct proc_metrics *m = metrics.lookup(&pid);
    if (!m) {
        struct proc_metrics zero = {};
        bpf_get_current_comm(&zero.comm, sizeof(zero.comm));
        metrics.update(&pid, &zero);
        m = metrics.lookup(&pid);
    }
    return m;
}

/*
 * Enqueue event: a sleeping thread woke up and was placed in the CPU run-queue
 */
TRACEPOINT_PROBE(sched, sched_wakeup) {
    u32 pid = args->pid;
    if (pid > 0) {
        u64 ts = bpf_ktime_get_ns();
        sched_start.update(&pid, &ts);
    }
    return 0;
}

/*
 * Enqueue event: a brand-new task was created and placed in the CPU run-queue
 */
TRACEPOINT_PROBE(sched, sched_wakeup_new) {
    u32 pid = args->pid;
    if (pid > 0) {
        u64 ts = bpf_ktime_get_ns();
        sched_start.update(&pid, &ts);
    }
    return 0;
}

/*
 * Scheduler run-queue stall & context switch probe
 */
TRACEPOINT_PROBE(sched, sched_switch) {
    u64 ts = bpf_ktime_get_ns();
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;

    if (prev_pid > 0) {
        struct proc_metrics *m = get_metrics(prev_pid);
        if (m) {
            // prev_state == 0 means TASK_RUNNING: the task was still runnable,
            // but the CPU kicked it off. That is an involuntary context switch (preemption).
            if (args->prev_state == 0) {
                m->involuntary_switches++;
                // Because it was preempted while still running, it re-enters the run queue:
                sched_start.update(&prev_pid, &ts);
            } else {
                // Task voluntarily went to sleep (waiting for I/O, timer, lock).
                // Do NOT record in sched_start because it is sleeping, not waiting in a run-queue!
                m->voluntary_switches++;
            }
        }
    }

    // next_pid was just scheduled onto a CPU.
    // Check if it was waiting in the run queue after a wakeup or preemption.
    if (next_pid > 0) {
        u64 *start_ts = sched_start.lookup(&next_pid);
        if (start_ts) {
            u64 delta = ts - *start_ts;
            // Record only real run-queue delays (< 10 seconds sanity guard)
            if (delta < 10000000000ULL) {
                struct proc_metrics *m = get_metrics(next_pid);
                if (m) {
                    m->total_stall_ns += delta;
                    m->stall_count++;
                }
            }
            sched_start.delete(&next_pid);
        }
    }

    return 0;
}

/*
 * Syscall latency entry & exit probes
 */
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    syscall_start.update(&tid, &ts);
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 *start_ts = syscall_start.lookup(&tid);
    if (!start_ts) return 0;

    u64 delta = bpf_ktime_get_ns() - *start_ts;
    syscall_start.delete(&tid);

    if (delta < 1000 || delta > 5000000000ULL) return 0;

    u32 pid = tid >> 32;
    struct proc_metrics *m = get_metrics(pid);
    if (m) {
        m->total_syscall_ns += delta;
        m->syscall_count++;
    }
    return 0;
}

/*
 * Page fault probe (major vs minor disk thrashing)
 */
TRACEPOINT_PROBE(exceptions, page_fault_user) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct proc_metrics *m = get_metrics(pid);
    if (m) {
        if (args->error_code & 1) {
            m->minor_faults++;
        } else {
            m->major_faults++;
        }
    }
    return 0;
}

/*
 * Futex / Mutex lock contention probes
 */
int trace_futex_enter(struct pt_regs *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    lock_start.update(&tid, &ts);
    return 0;
}

int trace_futex_return(struct pt_regs *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 *start_ts = lock_start.lookup(&tid);
    if (!start_ts) return 0;

    u64 delta = bpf_ktime_get_ns() - *start_ts;
    lock_start.delete(&tid);

    if (delta < 1000 || delta > 5000000000ULL) return 0;

    u32 pid = tid >> 32;
    struct proc_metrics *m = get_metrics(pid);
    if (m) {
        m->total_lock_wait_ns += delta;
        m->lock_wait_count++;
    }
    return 0;
}
