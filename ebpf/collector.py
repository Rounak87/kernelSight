import time
import json
import argparse
import requests
import os
import signal
import sys
from datetime import datetime

try:
    from bcc import BPF
except ImportError:
    BPF = None  # Handled in main() for non-Linux or testing environments

# Path to the kernel eBPF C probes program
C_SOURCE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collector.c")

# In-memory discovery cache to prevent disk I/O storms against /proc
_PID_SERVICE_CACHE = {}
_CACHE_TTL_SECONDS = 180

# Idle/housekeeping kernel threads that produce no application telemetry
IGNORED_KERNEL_COMM = {
    "swapper", "ksoftirqd", "kthreadd", "rcu_sched", "rcu_bh",
    "migration", "watchdog", "cpuhp", "idle", "kcompactd0"
}

# Common runtime interpreters where the binary name alone is uninformative
INTERPRETERS = (
    "python", "python3", "node", "nodejs", "ruby", "perl",
    "bash", "sh", "zsh", "java", "uvicorn", "gunicorn", "celery", "flask", "dotnet"
)


def resolve_service_name(pid: int, comm: str) -> str | None:
    """
    Dynamically discover the real application or service name on any Linux/EC2 host:
    1. Inspects /proc/<pid>/cgroup for systemd units (e.g. nginx.service -> nginx)
       and container runtimes (e.g. docker-<id>.scope).
    2. For interpreters (python, node, java), parses /proc/<pid>/cmdline to find
       the actual script, module, or application being executed.
    3. Falls back to a sanitized process name without hardcoding.
    """
    comm = comm.strip().strip("\x00")
    if not comm or comm in IGNORED_KERNEL_COMM:
        return None

    now = time.time()
    if pid in _PID_SERVICE_CACHE:
        cached_time, cached_name = _PID_SERVICE_CACHE[pid]
        if now - cached_time < _CACHE_TTL_SECONDS:
            return cached_name

    service_name = _discover_service_from_proc(pid, comm)
    _PID_SERVICE_CACHE[pid] = (now, service_name)
    return service_name


def _discover_service_from_proc(pid: int, comm: str) -> str:
    # 1. Check systemd unit or container cgroup
    cgroup_path = f"/proc/{pid}/cgroup"
    if os.path.exists(cgroup_path):
        try:
            with open(cgroup_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if ".service" in line:
                        part = line.split("/")[-1]
                        if part.endswith(".service"):
                            unit_name = part[:-8]
                            if unit_name not in ("systemd", "init", "user@"):
                                return unit_name
                    if "/docker/" in line or "docker-" in line:
                        cid = line.split("/")[-1].replace("docker-", "").replace(".scope", "")[:12]
                        return f"docker-{cid}"
        except Exception:
            pass

    # 2. For interpreters, check /proc/<pid>/cmdline for the executed script/app
    cmdline_path = f"/proc/{pid}/cmdline"
    if os.path.exists(cmdline_path):
        try:
            with open(cmdline_path, "rb") as f:
                raw = f.read()
            parts = [p.decode("utf-8", errors="ignore") for p in raw.split(b"\x00") if p]
            if parts:
                base_bin = os.path.basename(parts[0]).lower()
                if any(base_bin.startswith(interp) for interp in INTERPRETERS):
                    for arg in parts[1:]:
                        if arg.startswith("-"):
                            continue
                        script_name = os.path.basename(arg)
                        if script_name.endswith((".py", ".js", ".ts", ".rb", ".jar", ".sh")):
                            return script_name.rsplit(".", 1)[0]
                        if ":" in script_name:
                            return script_name.split(":")[0]
                        if len(script_name) > 2 and not script_name.startswith("/"):
                            return script_name
        except Exception:
            pass

    # 3. Clean up raw comm
    clean = comm.replace("/", "-").rstrip("-").strip()
    return clean or comm


def format_ns(ns):
    if ns < 1000:
        return f"{ns}ns"
    elif ns < 1_000_000:
        return f"{ns / 1000:.1f}us"
    elif ns < 1_000_000_000:
        return f"{ns / 1_000_000:.1f}ms"
    else:
        return f"{ns / 1_000_000_000:.2f}s"


def print_header():
    print("=" * 120)
    print(f"  kernel-aiops | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | kernel {os.uname().release}")
    print("=" * 120)
    print(f"{'PID':<8} {'SERVICE':<20} {'SCHED STALL':<14} {'INVOL SW':<10} "
          f"{'SYSCALL LAT':<14} {'SYSCALLS':<10} {'MAJ FAULT':<10} "
          f"{'LOCK WAIT':<14} {'LOCKS':<8}")
    print("-" * 120)


def collect_and_send(bpf_obj, endpoint=None):
    metrics_table = bpf_obj["metrics"]
    records = []

    for pid, m in metrics_table.items():
        pid_val = pid.value
        if pid_val < 100:
            continue

        comm = m.comm.decode("utf-8", errors="replace").strip("\x00")
        if not comm:
            continue

        service = resolve_service_name(pid_val, comm)
        if service is None:
            continue

        avg_stall = m.total_stall_ns / max(m.stall_count, 1)
        avg_syscall = m.total_syscall_ns / max(m.syscall_count, 1)
        avg_lock_wait = m.total_lock_wait_ns / max(m.lock_wait_count, 1)

        record = {
            "pid": pid_val,
            "process": comm,
            "service": service,
            "timestamp": time.time(),
            "total_stall_ns": m.total_stall_ns,
            "avg_stall_ns": int(avg_stall),
            "stall_count": m.stall_count,
            "involuntary_switches": m.involuntary_switches,
            "voluntary_switches": m.voluntary_switches,
            "total_syscall_ns": m.total_syscall_ns,
            "avg_syscall_ns": int(avg_syscall),
            "syscall_count": m.syscall_count,
            "major_faults": m.major_faults,
            "minor_faults": m.minor_faults,
            "total_lock_wait_ns": m.total_lock_wait_ns,
            "avg_lock_wait_ns": int(avg_lock_wait),
            "lock_wait_count": m.lock_wait_count,
        }

        records.append(record)

        print(f"{pid_val:<8} {service:<20} {format_ns(int(avg_stall)):<14} "
              f"{m.involuntary_switches:<10} {format_ns(int(avg_syscall)):<14} "
              f"{m.syscall_count:<10} {m.major_faults:<10} "
              f"{format_ns(int(avg_lock_wait)):<14} {m.lock_wait_count:<8}")

    metrics_table.clear()

    if endpoint and records:
        try:
            resp = requests.post(
                endpoint,
                json={"node": os.uname().nodename, "timestamp": time.time(), "metrics": records},
                timeout=2
            )
            status = f"sent {len(records)} records -> {resp.status_code}"
        except requests.exceptions.RequestException as e:
            status = f"send failed: {str(e)[:60]}"
    else:
        status = f"{len(records)} processes"

    print("-" * 120)
    print(f"  {status}")
    print("=" * 120)

    return records


def main():
    parser = argparse.ArgumentParser(description="kernel-aiops eBPF collector")
    parser.add_argument("--endpoint", type=str, default=None)
    parser.add_argument("--interval", type=int, default=1)
    parser.add_argument("--no-clear", action="store_true")
    args = parser.parse_args()

    if BPF is None:
        print("Error: BCC (python3-bpfcc) is required to run the collector.")
        print("Please run this collector on a Linux host with kernel headers and BCC installed.")
        sys.exit(1)

    if not os.path.exists(C_SOURCE_PATH):
        print(f"Error: eBPF C program not found at {C_SOURCE_PATH}")
        sys.exit(1)

    print(f"loading eBPF program from {C_SOURCE_PATH}...")
    b = BPF(src_file=C_SOURCE_PATH)

    # Attach futex lock contention kprobes across kernel versions (do_futex on 5.x, sys_futex on 6.x)
    futex_attached = False
    for fn in ("do_futex", "__x64_sys_futex", "sys_futex", "__arm64_sys_futex"):
        try:
            b.attach_kprobe(event=fn, fn_name="trace_futex_enter")
            b.attach_kretprobe(event=fn, fn_name="trace_futex_return")
            futex_attached = True
            break
        except Exception:
            continue
    if not futex_attached:
        print("Note: futex kprobe unavailable on this kernel symbol table.")

    print(f"collecting | interval={args.interval}s | endpoint={args.endpoint or 'local'}")

    def signal_handler(sig, frame):
        print("\nstopping collector")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    while True:
        if not args.no_clear:
            os.system("clear")
        print_header()
        collect_and_send(b, endpoint=args.endpoint)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
