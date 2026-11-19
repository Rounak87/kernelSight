"""
Diagnostic tool implementations for the LLM agent.

Each function is exposed as a native Gemini function-calling tool.
Tools 1 and 2 query live data from InfluxDB.
Tools 3 and 4 query structured config and log files.
"""

import os
import re
import yaml
import json
import logging
import shutil
import subprocess
import platform
from pathlib import Path
from pipeline.db import fetch_history, list_active_services

log = logging.getLogger(__name__)

_AGENT_DIR = Path(__file__).parent
_TOPOLOGY_PATH    = _AGENT_DIR / "topology.yaml"
_DEPLOYMENTS_PATH = _AGENT_DIR / "deployments.yaml"
_LOGS_DIR         = _AGENT_DIR / "logs"

_TOPOLOGY = {}
if _TOPOLOGY_PATH.exists():
    try:
        with open(_TOPOLOGY_PATH, encoding="utf-8") as f:
            _TOPOLOGY = yaml.safe_load(f) or {}
    except Exception as e:
        log.warning("Could not read topology.yaml: %s", e)

_DEPLOYMENTS = {}
if _DEPLOYMENTS_PATH.exists():
    try:
        with open(_DEPLOYMENTS_PATH, encoding="utf-8") as f:
            _DEPLOYMENTS = yaml.safe_load(f) or {}
    except Exception as e:
        log.warning("Could not read deployments.yaml: %s", e)


def query_metrics_history(service: str, metric: str, window: str = "30m") -> str:
    """
    Return recent time-series values for a specific kernel metric on a service.
    Window accepts InfluxDB duration strings: '5m', '30m', '1h', '7d'.
    """
    values = fetch_history(service, metric, window=window)
    if not values and window != "30d":
        values = fetch_history(service, metric, window="30d")
        if values:
            window = "30d"
    if not values:
        return json.dumps({"error": f"No data for service={service} metric={metric} window={window}"})
    summary = {
        "service": service,
        "metric": metric,
        "window": window,
        "count": len(values),
        "min": round(min(values), 2),
        "max": round(max(values), 2),
        "mean": round(sum(values) / len(values), 2),
        "last_value": round(values[-1], 2),
        "sample_tail": [round(v, 2) for v in values[-10:]],
    }
    return json.dumps(summary)


def get_service_topology(service: str) -> str:
    """
    Return upstream and downstream service dependencies for a given service.
    First checks topology configuration; if not defined, dynamically discovers
    dependencies from live Linux socket connections (ss) and systemd dependency trees.
    """
    entry = _TOPOLOGY.get("services", {}).get(service)
    if entry:
        return json.dumps({
            "service": service,
            "type": entry.get("type"),
            "description": entry.get("description"),
            "upstream": entry.get("upstream", []),
            "downstream": entry.get("downstream", []),
            "source": "static_topology",
        })

    # Live discovery on host if running on Linux / EC2
    upstream = []
    downstream = []
    inferred_type = "application"
    description = f"Dynamically discovered service '{service}'"

    if platform.system() == "Linux":
        # Check systemd dependencies
        if shutil.which("systemctl"):
            try:
                res = subprocess.run(
                    ["systemctl", "show", service, "-p", "Requires,Wants,After,Before,Description"],
                    capture_output=True, text=True, timeout=2
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        if line.startswith("Requires=") or line.startswith("After="):
                            deps = [d.replace(".service", "") for d in line.split("=", 1)[1].split() if d]
                            downstream.extend([d for d in deps if d not in downstream and d != service])
                        elif line.startswith("Before="):
                            deps = [d.replace(".service", "") for d in line.split("=", 1)[1].split() if d]
                            upstream.extend([d for d in deps if d not in upstream and d != service])
                        elif line.startswith("Description="):
                            desc = line.split("=", 1)[1].strip()
                            if desc:
                                description = desc
            except Exception:
                pass

        # Check live network connections using ss
        if shutil.which("ss"):
            try:
                res = subprocess.run(
                    ["ss", "-tupn"],
                    capture_output=True, text=True, timeout=2
                )
                if res.returncode == 0 and service in res.stdout:
                    for line in res.stdout.splitlines():
                        if service in line:
                            parts = line.split()
                            if len(parts) >= 5:
                                peer = parts[4]
                                if ":" in peer and not peer.startswith("127.0.0.1"):
                                    downstream.append(peer)
            except Exception:
                pass

    # Infer type if kernel thread or daemon
    if any(k in service for k in ("jbd2", "kworker", "dm-", "nvme", "ext4", "btrfs")):
        inferred_type = "kernel-daemon"
        description = f"Kernel block / storage subsystem daemon ({service})"
    elif service.endswith("d") or service.startswith("systemd-"):
        inferred_type = "system-daemon"

    return json.dumps({
        "service": service,
        "type": inferred_type,
        "description": description,
        "upstream": upstream[:5],
        "downstream": downstream[:5],
        "source": "dynamic_host_discovery",
    })


def get_recent_deployments(service: str, hours: int = 24) -> str:
    """
    Return deployment and restart events for a service in the last N hours.
    Queries live systemd lifecycle events and git commit history, falling back to static logs.
    """
    service_key = service.split("/")[0]
    records = _DEPLOYMENTS.get("deployments", {}).get(service_key, [])
    if records:
        return json.dumps({
            "service": service,
            "deployments": records,
            "count": len(records),
            "source": "deployment_manifest",
        })

    live_events = []

    # 1. Check systemd unit restart / startup time on Linux
    if platform.system() == "Linux" and shutil.which("systemctl"):
        try:
            res = subprocess.run(
                ["systemctl", "show", service, "-p", "ActiveEnterTimestamp,ExecMainStartTimestamp"],
                capture_output=True, text=True, timeout=2
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        if v.strip():
                            live_events.append({"event": k, "timestamp": v.strip(), "source": "systemd"})
        except Exception:
            pass

    # 2. Check local git log if service repository exists on the host
    if shutil.which("git"):
        try:
            res = subprocess.run(
                ["git", "log", "-n", "3", "--pretty=format:%h - %an (%ar): %s"],
                capture_output=True, text=True, timeout=2
            )
            if res.returncode == 0 and res.stdout.strip():
                for commit in res.stdout.splitlines():
                    live_events.append({"commit": commit.strip(), "source": "git_log"})
        except Exception:
            pass

    return json.dumps({
        "service": service,
        "deployments": live_events,
        "count": len(live_events),
        "note": "Queried live host systemd and repository state." if live_events else "No deployment or restart events detected in window.",
    })


def search_logs(service: str, pattern: str) -> str:
    """
    Search service logs for lines matching a keyword or pattern.
    Checks live system logs (journalctl / dmesg / /var/log) first, falling back to local files.
    Returns up to 10 matching lines with timestamps.
    """
    matches = []
    source = "none"

    # 1. Try live systemd journalctl on Linux
    if platform.system() == "Linux" and shutil.which("journalctl"):
        try:
            # Query service unit or comm
            cmd = ["journalctl", "-u", service, "-n", "150", "--no-pager"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if res.returncode == 0 and res.stdout.strip() and "No entries" not in res.stdout:
                regex = re.compile(pattern, re.IGNORECASE)
                lines = res.stdout.splitlines()
                matches = [l for l in lines if regex.search(l)][:10]
                if matches:
                    source = "journalctl"
        except Exception:
            pass

        # If kernel daemon, also query dmesg / kernel ring buffer
        if not matches and any(k in service for k in ("jbd2", "nvme", "multipathd", "dm-")):
            try:
                res = subprocess.run(["dmesg", "-T"], capture_output=True, text=True, timeout=2)
                if res.returncode == 0 and res.stdout.strip():
                    lines = res.stdout.splitlines()[-200:]
                    regex = re.compile(pattern, re.IGNORECASE)
                    matches = [l for l in lines if regex.search(l)][:10]
                    if matches:
                        source = "dmesg"
            except Exception:
                pass

    # 2. Fallback to local files in logs/
    if not matches:
        service_key = service.split("/")[0].replace("-", "-")
        log_candidates = [
            _LOGS_DIR / f"{service_key}.log",
            _LOGS_DIR / f"{service}.log",
            Path(f"/var/log/{service}.log"),
        ]

        for candidate in log_candidates:
            if candidate.exists():
                try:
                    lines = candidate.read_text(encoding="utf-8", errors="ignore").splitlines()
                    regex = re.compile(pattern, re.IGNORECASE)
                    matches = [l for l in lines if regex.search(l)][:10]
                    if matches:
                        source = str(candidate)
                        break
                except Exception:
                    pass

    return json.dumps({
        "service": service,
        "pattern": pattern,
        "match_count": len(matches),
        "matches": matches,
        "source": source,
        "note": "Matches found in live system logs." if matches else f"No log entries matching '{pattern}' found."
    })


TOOL_FUNCTIONS = {
    "query_metrics_history": query_metrics_history,
    "get_service_topology":  get_service_topology,
    "get_recent_deployments": get_recent_deployments,
    "search_logs":           search_logs,
}
