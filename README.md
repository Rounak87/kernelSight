# KernelSight: Kernel-Native, Real-Time Bottleneck Diagnosis for Distributed Systems

[![eBPF](https://img.shields.io/badge/eBPF-BCC%20%2F%20C-orange.svg)](https://ebpf.io/)
[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)
[![InfluxDB](https://img.shields.io/badge/InfluxDB-2.7%20Flux-22ADF6.svg)](https://www.influxdata.com/)
[![Grafana](https://img.shields.io/badge/Grafana-Provisioned-F46800.svg)](https://grafana.com/)
[![Gemini](https://img.shields.io/badge/Agent-Google%20GenAI%20ReAct-8E75B2.svg)](https://ai.google.dev/)

**KernelSight** is a zero-instrumentation, kernel-native observability and root-cause diagnosis platform. Using **eBPF** tracepoints and kprobes directly inside the Linux kernel, it captures per-process scheduler stalls, futex lock contention, syscall latencies, and page faults at 1-second resolution—streaming telemetry into a **Tri-Model ML Engine** (Isolation Forest, Granger Causality DAG, OLS Saturation Forecaster) and an **Autonomous LLM Diagnostic Agent** for structured, evidence-backed Root Cause Analysis (RCA).

---

## System Architecture

```text
  ╔══════════════════════════════════════════════════════════════════════════════════╗
  ║  LINUX KERNEL SPACE (5.15+ / 6.8+)                             ebpf/collector.c  ║
  ╠══════════════════════════════════════════════════════════════════════════════════╣
  ║   ┌─────────────────────────┐  ┌─────────────────────────┐  ┌─────────────────┐  ║
  ║   │ sched_wakeup / switch   │  │ raw_syscalls:enter/exit │  │ page_fault_user │  ║
  ║   └────────────┬────────────┘  └────────────┬────────────┘  └────────┬────────┘  ║
  ║                │               ┌────────────┴────────────┐           │           ║
  ║                │               │ kprobe: do_futex / sys  │           │           ║
  ║                │               └────────────┬────────────┘           │           ║
  ║                ▼                            ▼                        ▼           ║
  ║   ┌───────────────────────────────────────────────────────────────────────────┐  ║
  ║   │  In-Kernel BPF Hash Maps (metrics, sched_start, syscall_start, lock_start)│  ║
  ║   └─────────────────────────────────────┬─────────────────────────────────────┘  ║
  ╚═════════════════════════════════════════╪════════════════════════════════════════╝
                                            │  BCC Userspace Aggregation (1s)
                                            ▼
  ╔══════════════════════════════════════════════════════════════════════════════════╗
  ║  USER-SPACE COLLECTOR & DISCOVERY                              ebpf/collector.py ║
  ╠══════════════════════════════════════════════════════════════════════════════════╣
  ║  • Dynamic service resolution via /proc/<pid>/cgroup (systemd/Docker) & cmdline  ║
  ║  • Batched HTTP/JSON telemetry stream (direct LAN or ngrok TLS tunnel)           ║
  ╚═════════════════════════════════════════╤════════════════════════════════════════╝
                                            │  POST /ingest
                                            ▼
  ╔══════════════════════════════════════════════════════════════════════════════════╗
  ║  INGESTION & TIME-SERIES STORAGE                pipeline/ingest.py ──► InfluxDB  ║
  ╠══════════════════════════════════════════════════════════════════════════════════╣
  ║  FastAPI Receiver (:5000) ──► InfluxDB 2.7 (:8086 · kernel_metrics · Flux)       ║
  ╚══════════════════╤═══════════════════════════════════════════╤═══════════════════╝
                     │  Flux Queries                             │  Live Stream
                     ▼                                           ▼
  ┌──────────────────────────────────────┐    ┌──────────────────────────────────────┐
  │  TRI-MODEL ML ENGINE        models/  │    │  GRAFANA COCKPIT              :3000  │
  ├──────────────────────────────────────┤    ├──────────────────────────────────────┤
  │  1. Isolation Forest                 │    │  • Auto-provisioned Flux Datasource  │
  │     6D feature vector · score > 0.85 │    │  • Stall, Lock, Fault & Preempt UI   │
  │  2. Granger Causality DAG            │    │  • Critical Threshold Alerts         │
  │     VAR F-tests (p < 0.05, lag 1-3s) │    └──────────────────────────────────────┘
  │  3. Saturation Forecaster            │
  │     OLS trend · Time-to-Saturation   │
  └──────────────────┬───────────────────┘
                     │  Anomaly & Causal Incident Brief
                     ▼
  ╔══════════════════════════════════════════════════════════════════════════════════╗
  ║  AUTONOMOUS DIAGNOSTIC AGENT & COMMAND CENTER      agent/core.py + api/server.py ║
  ╠══════════════════════════════════════════════════════════════════════════════════╣
  ║  ReAct Tool-Calling Loop (Google GenAI)          Interactive Web Console (:8000) ║
  ║   ├── query_metrics_history()  ──► InfluxDB       • Live Fleet Health Matrix     ║
  ║   ├── get_service_topology()   ──► ss / systemd   • Anomaly & TTS Indicators     ║
  ║   ├── get_recent_deployments() ──► git / systemd  • One-Click AI Investigation   ║
  ║   └── search_logs()            ──► journalctl     • Structured JSON RCA Reports  ║
  ╚══════════════════════════════════════════════════════════════════════════════════╝
```

---

## Kernel Instrumentation (`ebpf/collector.c`)

All telemetry collection occurs inside kernel memory via BCC-compiled C probes, eliminating application-level SDKs, sidecar proxies, or code changes:

| Metric | Kernel Hook | What It Captures | Failure Mode Diagnosed |
| :--- | :--- | :--- | :--- |
| `avg_stall_ns` | `sched:sched_wakeup`, `sched_wakeup_new`, `sched_switch` | True run-queue latency (enqueue to CPU execution, excluding voluntary sleep) | CPU starvation & run-queue saturation |
| `involuntary_switches` | `sched:sched_switch` (`prev_state == 0`) | Forced scheduler preemptions while task remained `TASK_RUNNING` | Thread oversubscription & CPU contention |
| `avg_syscall_ns` | `raw_syscalls:sys_enter` / `sys_exit` | Round-trip system call execution duration (`1us – 5s` filter) | Blocked disk I/O, slow sockets, kernel waits |
| `major_faults` | `exceptions:page_fault_user` | Page faults requiring synchronous disk/swap reads (`!(error_code & 1)`) | Host RAM exhaustion & swap thrashing |
| `avg_lock_wait_ns` | `kprobe/kretprobe` (`do_futex` / `__x64_sys_futex` / `sys_futex`) | Time spent blocked waiting to acquire userspace mutex/futex locks | Thread lock contention & GIL bottlenecks |

### Dynamic Service Discovery (`ebpf/collector.py`)
Instead of relying on static process maps, the user-space collector dynamically resolves service names on any Linux host:
1. **Systemd & Containers**: Parses `/proc/<pid>/cgroup` for unit names (`nginx.service` $\rightarrow$ `nginx`) and Docker container scopes (`docker-<id>`).
2. **Interpreted Runtimes**: For `python3`, `node`, `java`, `uvicorn`, etc., inspects `/proc/<pid>/cmdline` to extract the actual script, module, or JAR name.
3. **Low Overhead**: Uses an in-memory PID cache (180s TTL) to avoid `/proc` I/O overhead during 1-second collection intervals.

---

## Analytical & Diagnostic Pipeline

### 1. Tri-Model ML Engine (`models/`)
* **Anomaly Detection (`models/anomaly_detector.py`)**: Trains an **Isolation Forest** over a 6-dimensional behavioral baseline (`avg_stall_ns`, `involuntary_switches`, `avg_syscall_ns`, `major_faults`, `avg_lock_wait_ns`, `lock_wait_count`). Services scoring above **`0.85`** are escalated.
* **Causal DAG Construction (`models/causal_engine.py`)**: Runs pairwise **Granger Causality** (Vector Autoregression $F$-tests across lags `1..3` seconds, $p < 0.05$) on active metrics, then computes **Net Causal Influence** (`out_degree - in_degree`) to isolate the initiating root-cause metric from downstream symptoms.
* **Saturation Forecaster (`models/forecaster.py`)**: Fits Ordinary Least Squares (OLS) linear regression on the degraded metric trajectory to compute **Time-to-Saturation (TTS)** against operational thresholds (`100ms` scheduler stall, `50ms` lock wait, `20ms` syscall latency, `50` major faults/s, `500` preemptions/s).

### 2. Autonomous Diagnostic Agent (`agent/`)
When an incident is triggered, `DiagnosticAgent` (`agent/core.py`) runs a multi-turn **ReAct tool-calling loop** using the Google GenAI SDK (`gemini-3.5-flash-lite`) with four live host/telemetry tools in `agent/tools.py`:
* `query_metrics_history`: Pulls Flux statistical summaries (`min`, `max`, `mean`, `last_value`, `sample_tail`) from InfluxDB.
* `get_service_topology`: Queries live host socket connections (`ss -tupn`) and `systemctl` dependency trees (with `topology.yaml` fallback for offline analysis).
* `get_recent_deployments`: Inspects live `systemctl` unit restart timestamps and `git log` history (with `deployments.yaml` fallback).
* `search_logs`: Queries `journalctl`, kernel ring buffer (`dmesg -T`), and `/var/log` (with local `agent/logs/` fallback).

Every factual claim in the final JSON RCA report is grounded in verified tool outputs.

---

## Engineering Design Rationale

* **True Run-Queue Latency vs. Sleep Time**: Measuring `sched_switch` exit-to-entry blindly counts voluntary `sleep()` duration as scheduler latency. KernelSight pairs `sched:sched_wakeup` / `sched_wakeup_new` with `sched:sched_switch` (`prev_state == 0` for preemptions) so idle daemons report microsecond baselines and real CPU starvation stands out immediately.
* **Granger Causality over Pearson Correlation**: Correlation cannot distinguish cause from effect. Pairwise VAR $F$-tests capture temporal precedence—isolating the single originating kernel bottleneck even when a failure cascades across multiple downstream services.
* **Tool-Calling ReAct over Context Stuffing**: Injecting raw high-frequency time-series into an LLM prompt overflows context limits and degrades reasoning. Giving the agent targeted query tools keeps token usage minimal and produces auditable, deterministic RCA reports.
