"""
performance/overhead_analysis.py
Tejas — Performance overhead analysis.

Measures direct syscall vs full mediation stack.
Run: python -m performance.overhead_analysis
"""

import time
import json
import statistics
from typing import Callable

from database.models             import init_db
from auth_rbac.auth_controller   import register_user, login_user, logout_user
from auth_rbac.roles             import load_permissions
from auth_rbac.session_manager   import validate_session
from policy_engine.policy_loader import load_policies
from policy_engine.policy_evaluator import evaluate

ITERATIONS = 500
BENCH_USER = "__bench__"
BENCH_PASS = "BenchPass1"


def _benchmark(label: str, fn: Callable, n: int = ITERATIONS) -> dict:
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    return {
        "label":     label,
        "mean_ms":   round(statistics.mean(times),   4),
        "median_ms": round(statistics.median(times), 4),
        "stdev_ms":  round(statistics.stdev(times),  4),
        "min_ms":    round(min(times), 4),
        "max_ms":    round(max(times), 4),
    }


def run(token: str) -> list[dict]:
    results = []

    # 1. Baseline: raw file read
    def direct_read():
        with open(__file__, "r") as f:
            f.read(64)
    results.append(_benchmark("Direct file read (no wrapper)", direct_read))

    # 2. RBAC permission check only
    from auth_rbac.roles import can_perform
    results.append(_benchmark("RBAC permission check only",
                               lambda: can_perform("developer", "file_read")))

    # 3. Policy evaluation only
    results.append(_benchmark("Policy engine evaluation only",
                               lambda: evaluate("file_read", "developer", {"risk_score": 0.0})))

    # 4. JWT session validation
    results.append(_benchmark("JWT session validation",
                               lambda: validate_session(token)))

    # 5. Full mediation: auth + RBAC + policy (no syscall)
    def full_stack():
        s = validate_session(token)
        if not s["valid"]:
            return
        from auth_rbac.roles import can_perform
        can_perform(s["role"], "file_read")
        evaluate("file_read", s["role"], {"risk_score": 0.0})
    results.append(_benchmark("Full mediation stack (no syscall)", full_stack))

    # 6. Full mediation + actual syscall
    def full_stack_with_syscall():
        s = validate_session(token)
        if not s["valid"]:
            return
        from auth_rbac.roles import can_perform
        can_perform(s["role"], "file_read")
        evaluate("file_read", s["role"], {"risk_score": 0.0})
        with open(__file__, "r") as f:
            f.read(64)
    results.append(_benchmark("Full mediation + file syscall", full_stack_with_syscall))

    return results


def print_report(results: list[dict]):
    baseline = results[0]["mean_ms"]
    print("\n" + "═" * 74)
    print("  PERFORMANCE OVERHEAD — Secure Syscall Gateway Mediation Layer")
    print("═" * 74)
    print(f"  {'Benchmark':<46} {'Mean':>8}  {'Median':>8}  {'Overhead'}")
    print("─" * 74)
    for r in results:
        overhead = ""
        if r["label"] != results[0]["label"] and baseline > 0:
            delta = r["mean_ms"] - baseline
            pct   = delta / baseline * 100
            overhead = f"+{delta:.4f}ms (+{pct:.0f}%)"
        print(f"  {r['label']:<46} {r['mean_ms']:>7.4f}ms  {r['median_ms']:>7.4f}ms  {overhead}")
    print("─" * 74)
    full = results[-1]
    ratio = full["mean_ms"] / baseline if baseline > 0 else 0
    print(f"\n  Total mediation overhead : {full['mean_ms'] - baseline:.4f}ms per call")
    print(f"  Overhead ratio           : {ratio:.2f}x vs direct syscall")
    print(f"  Samples per benchmark    : {ITERATIONS} iterations")
    print("═" * 74 + "\n")


def save_report(results: list[dict]):
    with open("performance/benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("  [Saved] performance/benchmark_results.json")


if __name__ == "__main__":
    init_db()
    load_permissions()
    load_policies()

    register_user(BENCH_USER, BENCH_PASS, "developer")
    r = login_user(BENCH_USER, BENCH_PASS)
    token = r.get("token")

    if not token:
        print("[ERROR] Could not create benchmark session.")
        exit(1)

    print(f"[Benchmark] Running {ITERATIONS} iterations per case...\n")
    results = run(token)
    print_report(results)
    save_report(results)

    logout_user(token)

    from database.db import get_connection
    conn = get_connection()
    conn.execute("DELETE FROM users WHERE username = ?", (BENCH_USER,))
    conn.commit()
    conn.close()
    print("[Benchmark] Complete.")