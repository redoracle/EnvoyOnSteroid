"""Loopback-only controlled WAF performance and memory regression.

This tests the demo Compose stack, not production capacity or a formal
long-duration memory-leak guarantee. All inputs are synthetic.
"""

import argparse
import http.client
import ipaddress
import json
import math
import pathlib
import re
import statistics
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

_UNITS = {
    "B": 1, "kB": 1000, "MB": 1000**2, "GB": 1000**3,
    "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3,
}


def parse_memory_mib(value):
    first = value.split("/", 1)[0].strip()
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([A-Za-z]+)", first)
    if not match or match.group(2) not in _UNITS:
        raise ValueError("Unknown Docker memory-usage format")
    return float(match.group(1)) * _UNITS[match.group(2)] / 1024**2


def percentile(values, pct):
    if not values:
        raise ValueError("Cannot compute percentile without observations")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * pct / 100) - 1)]


def assess(report):
    problems = []
    if report["failures"]:
        problems.append("Unexpected HTTP status/payload or transport failure")
    if report["p95_latency_ms"] > 2500:
        problems.append("p95 latency exceeds controlled 2500 ms guardrail")
    if report["observed_rps"] < 0.7 * report["target_rps"]:
        problems.append("Observed throughput below 70% of requested rate")
    if report["memory_peak_mib"] > 900:
        problems.append("Envoy working-set memory above 900 MiB")
    if (
        report["duration_seconds"] >= 180
        and len(report["memory_samples_mib"]) >= 10
        and report["memory_growth_mib"] > 160
    ):
        problems.append("Extended run memory growth exceeded 160 MiB")
    return problems


def check_local_origin(base_url):
    parsed = urlsplit(base_url)
    if parsed.scheme != "http" or parsed.path not in ("", "/"):
        raise ValueError("Only a loopback HTTP origin is permitted")
    try:
        local = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        local = parsed.hostname == "localhost"
    if not local or parsed.username or parsed.password or parsed.query:
        raise ValueError("Only a loopback HTTP origin is permitted")
    return parsed.hostname, parsed.port or 80


def compose_container_id(service):
    result = subprocess.run(
        ("docker", "compose", "ps", "--quiet", service),
        check=True, capture_output=True, text=True, timeout=15,
    )
    container = result.stdout.strip()
    if not container:
        raise RuntimeError("Missing demo Compose service: " + service)
    return container


def memory_mib(container):
    result = subprocess.run(
        ("docker", "stats", "--no-stream", "--format",
         "{{.MemUsage}}", container),
        check=True, capture_output=True, text=True, timeout=12,
    )
    return parse_memory_mib(result.stdout.strip())


def probe(index, host, port):
    kind = index % 4
    if kind == 0:
        method, path, body, expected = "GET", f"/get?qa_soak={index}", None, 200
    elif kind == 1:
        method, path, expected = "POST", "/post", 200
        body = json.dumps({"message": "synthetic-soak", "count": index})
    elif kind == 2:
        method, path, body, expected = "GET", "/__waf_test_block", None, 403
    else:
        method, path, expected = "POST", "/post", 403
        body = json.dumps({"message": "__waf_test_payload"})
    headers = {"Accept": "application/json"}
    if method == "POST":
        headers["Content-Type"] = "application/json"
    start = time.monotonic()
    connection = http.client.HTTPConnection(host, port, timeout=6)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read(1024 * 1024 + 1)
        elapsed = (time.monotonic() - start) * 1000
        if response.status != expected or len(payload) > 1024 * 1024:
            return False, elapsed, kind
        if kind == 0:
            valid = json.loads(payload)["args"]["qa_soak"] == [str(index)]
        elif kind == 1:
            valid = json.loads(payload)["json"] == {
                "message": "synthetic-soak", "count": index
            }
        else:
            valid = True
        return valid, elapsed, kind
    except (OSError, ValueError, TypeError, KeyError):
        return False, (time.monotonic() - start) * 1000, kind
    finally:
        connection.close()


def run_soak(host, port, *, duration, rate, workers):
    container = compose_container_id("envoy")
    memory = [memory_mib(container)]
    last_sample = time.monotonic()
    started = time.monotonic()
    futures = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        iteration = 0
        while True:
            at = started + iteration / rate
            if at >= started + duration:
                break
            if at > time.monotonic():
                time.sleep(at - time.monotonic())
            futures.append(executor.submit(probe, iteration, host, port))
            iteration += 1
            if time.monotonic() - last_sample >= 5:
                memory.append(memory_mib(container))
                last_sample = time.monotonic()
        results = [future.result(timeout=15) for future in futures]
    memory.append(memory_mib(container))
    elapsed = time.monotonic() - started
    latencies = [ms for _, ms, _ in results]
    n = min(3, len(memory))
    return {
        "duration_seconds": duration,
        "elapsed_seconds": round(elapsed, 3),
        "target_rps": rate,
        "observed_rps": round(len(results) / elapsed, 3),
        "workers": workers,
        "request_count": len(results),
        "failures": sum(not good for good, _, _ in results),
        "scenario_counts": {
            str(k): sum(kind == k for _, _, kind in results)
            for k in range(4)
        },
        "p50_latency_ms": round(percentile(latencies, 50), 3),
        "p95_latency_ms": round(percentile(latencies, 95), 3),
        "p99_latency_ms": round(percentile(latencies, 99), 3),
        "memory_samples_mib": [round(value, 2) for value in memory],
        "memory_peak_mib": round(max(memory), 2),
        "memory_growth_mib": round(
            statistics.median(memory[-n:]) - statistics.median(memory[:n]), 2
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--rate", type=int, default=6)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not 10 <= args.duration <= 900:
        parser.error("duration must be between 10 and 900 seconds")
    if not 1 <= args.rate <= 30 or not 1 <= args.workers <= 16:
        parser.error("rate must be 1–30 and workers must be 1–16")
    host, port = check_local_origin(args.base_url)
    report = run_soak(
        host, port, duration=args.duration,
        rate=args.rate, workers=args.workers,
    )
    report["violations"] = assess(report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(
        "WAF soak: " + json.dumps({
            key: value for key, value in report.items()
            if key != "memory_samples_mib"
        }, sort_keys=True)
    )
    if report["violations"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
