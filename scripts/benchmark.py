#!/usr/bin/env python3
"""Measure this build; timings include Python/ctypes overhead and allocations."""
import argparse
import ctypes
import hashlib
import json
import math
from pathlib import Path
import platform
import statistics
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--iterations", default=100, type=int)
    args = parser.parse_args()
    if args.iterations < 100:
        parser.error("use at least 100 measured iterations")
    lib = ctypes.CDLL(str(args.library.resolve()))
    for name, n in [("keygen", 2), ("encaps", 3), ("decaps", 3)]:
        fn = getattr(lib, "zupt_mlkem768_" + name)
        fn.argtypes = [ctypes.c_void_p] * n
        fn.restype = ctypes.c_int
    pk, sk = ctypes.create_string_buffer(1184), ctypes.create_string_buffer(2400)
    ct, ss, recovered = (ctypes.create_string_buffer(n) for n in [1088, 32, 32])
    results = {}
    for name, fn in [
        ("keygen", lambda: lib.zupt_mlkem768_keygen(pk, sk)),
        ("encaps", lambda: lib.zupt_mlkem768_encaps(ct, ss, pk)),
        ("decaps", lambda: lib.zupt_mlkem768_decaps(recovered, ct, sk))]:
        for _ in range(10):
            assert fn() == 0
        samples = []
        for _ in range(args.iterations):
            start = time.perf_counter_ns()
            ret = fn()
            samples.append((time.perf_counter_ns() - start) / 1000)
            assert ret == 0
        ordered = sorted(samples)
        results[name] = {"unit": "microseconds", "samples": len(samples),
                         "median": statistics.median(samples),
                         "p95": ordered[math.ceil(.95 * len(ordered)) - 1],
                         "p99": ordered[math.ceil(.99 * len(ordered)) - 1]}
    assert recovered.raw == ss.raw
    cpu = platform.processor()
    if Path("/proc/cpuinfo").exists():
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    report = {"library_sha256": hashlib.sha256(args.library.read_bytes()).hexdigest(),
              "platform": platform.system(), "architecture": platform.machine(),
              "cpu": cpu, "python": platform.python_version(),
              "method": "10 warmups; perf_counter_ns; Python/ctypes overhead included; nearest-rank percentiles",
              "scope": "one process, one machine, native ML-KEM-768 only; no cross-platform or whole-SDK claim",
              "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
