#!/usr/bin/env python3
"""Sample Linux process resources and QuicFuscate Prometheus metrics."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProcessSample:
    start_ticks: int
    cpu_ticks: int
    rss_bytes: int
    high_water_bytes: int


STOP_REQUESTED = False


def request_stop(_signum: int, _frame: object) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True


def read_process(pid: int, page_size: int) -> ProcessSample:
    stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    closing_parenthesis = stat_text.rfind(")")
    if closing_parenthesis < 0:
        raise RuntimeError(f"malformed /proc/{pid}/stat")
    stat_fields = stat_text[closing_parenthesis + 2 :].split()
    status_lines = Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines()
    high_water_kib = next(
        (int(fields[1]) for line in status_lines if (fields := line.split())[:1] == ["VmHWM:"]),
        0,
    )
    return ProcessSample(
        start_ticks=int(stat_fields[19]),
        cpu_ticks=int(stat_fields[11]) + int(stat_fields[12]),
        rss_bytes=int(stat_fields[21]) * page_size,
        high_water_bytes=high_water_kib * 1024,
    )


def fetch_metrics(host: str, port: int) -> dict[str, int]:
    request = f"GET /metrics HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    with socket.create_connection((host, port), timeout=1.0) as connection:
        connection.sendall(request)
        response = bytearray()
        while chunk := connection.recv(65536):
            response.extend(chunk)
    header, separator, body = bytes(response).partition(b"\r\n\r\n")
    if not separator or b" 200 " not in header.splitlines()[0]:
        raise RuntimeError("metrics endpoint did not return HTTP 200")

    metrics: dict[str, int] = {}
    for raw_line in body.decode("utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, raw_value = line.rsplit(maxsplit=1)
        value = float(raw_value)
        if not value.is_integer():
            continue
        metrics[name] = int(value)
    return metrics


def metric_delta(first: dict[str, int], last: dict[str, int], name: str) -> int:
    if name not in first or name not in last:
        raise RuntimeError(f"required metric is absent: {name}")
    delta = last[name] - first[name]
    if delta < 0:
        raise RuntimeError(f"counter regressed: {name}")
    return delta


def summarize(
    process_samples: dict[int, list[ProcessSample]],
    metric_samples: list[dict[str, int]],
    elapsed_seconds: float,
    clock_ticks: int,
) -> dict[str, object]:
    cpu_ticks = 0
    process_summaries: dict[str, dict[str, int]] = {}
    sample_count = min(len(samples) for samples in process_samples.values())
    peak_rss_bytes = max(
        sum(process_samples[pid][index].rss_bytes for pid in process_samples)
        for index in range(sample_count)
    )
    peak_high_water_bytes = sum(
        max(sample.high_water_bytes for sample in samples)
        for samples in process_samples.values()
    )
    for pid, samples in process_samples.items():
        if len(samples) < 2:
            raise RuntimeError(f"insufficient process samples for PID {pid}")
        if samples[0].start_ticks != samples[-1].start_ticks:
            raise RuntimeError(f"PID identity changed while sampling: {pid}")
        cpu_ticks += samples[-1].cpu_ticks - samples[0].cpu_ticks
        process_summaries[str(pid)] = {
            "cpu_ticks_delta": samples[-1].cpu_ticks - samples[0].cpu_ticks,
            "peak_high_water_bytes": max(sample.high_water_bytes for sample in samples),
            "peak_rss_bytes": max(sample.rss_bytes for sample in samples),
            "start_ticks": samples[0].start_ticks,
        }

    if len(metric_samples) < 2:
        raise RuntimeError("insufficient metrics samples")
    first_metrics = metric_samples[0]
    last_metrics = metric_samples[-1]
    allocation_names = {
        "thread_local": 'quicfuscate_mem_pool_allocations_total{source="thread_local"}',
        "shared_queue": 'quicfuscate_mem_pool_allocations_total{source="shared_queue"}',
        "grow": 'quicfuscate_mem_pool_allocations_total{source="grow"}',
        "ephemeral": 'quicfuscate_mem_pool_allocations_total{source="ephemeral"}',
        "body_pool": "quicfuscate_body_pool_allocations_total",
    }
    allocation_deltas = {
        source: metric_delta(first_metrics, last_metrics, name)
        for source, name in allocation_names.items()
    }
    pending_packet_name = "quicfuscate_tun_downlink_backpressure_pending_packets"
    pending_byte_name = "quicfuscate_tun_downlink_backpressure_pending_bytes"
    rate_limit_name = "quicfuscate_rate_limited_total"
    for required_name in (pending_packet_name, pending_byte_name, rate_limit_name):
        if any(required_name not in sample for sample in metric_samples):
            raise RuntimeError(f"required metric is absent: {required_name}")

    return {
        "allocation_deltas": allocation_deltas,
        "cpu_one_core_percent": cpu_ticks / clock_ticks / elapsed_seconds * 100.0,
        "duration_seconds": elapsed_seconds,
        "metric_samples": len(metric_samples),
        "peak_pending_bytes": max(sample[pending_byte_name] for sample in metric_samples),
        "peak_pending_packets": max(sample[pending_packet_name] for sample in metric_samples),
        "peak_process_high_water_bytes": peak_high_water_bytes,
        "peak_process_rss_bytes": peak_rss_bytes,
        "process_count": len(process_samples),
        "processes": process_summaries,
        "rate_limited_delta": metric_delta(first_metrics, last_metrics, rate_limit_name),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", action="append", type=int, required=True)
    parser.add_argument("--metrics-host", default="127.0.0.1")
    parser.add_argument("--metrics-port", type=int, required=True)
    parser.add_argument("--interval", type=float, default=0.2)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.interval <= 0:
        raise ValueError("--interval must be positive")
    pids = tuple(dict.fromkeys(args.pid))
    if any(pid <= 0 for pid in pids):
        raise ValueError("--pid values must be positive")
    if args.output.exists():
        raise FileExistsError(f"refusing to replace existing output: {args.output}")

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    page_size = os.sysconf("SC_PAGE_SIZE")
    clock_ticks = os.sysconf("SC_CLK_TCK")
    process_samples: dict[int, list[ProcessSample]] = {pid: [] for pid in pids}
    metric_samples: list[dict[str, int]] = []
    started = time.monotonic()

    while True:
        for pid in pids:
            process_samples[pid].append(read_process(pid, page_size))
        metric_samples.append(fetch_metrics(args.metrics_host, args.metrics_port))
        if STOP_REQUESTED:
            break
        time.sleep(args.interval)

    elapsed_seconds = time.monotonic() - started
    summary = summarize(process_samples, metric_samples, elapsed_seconds, clock_ticks)
    args.output.write_text(json.dumps(summary, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
