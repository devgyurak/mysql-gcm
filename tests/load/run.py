#!/usr/bin/env python3
"""Load test: server-side decrypt + LIKE against the AES_DECRYPT baseline.

The question this answers is the one docs/design.md §1.2 raises with estimates
rather than measurements: is a server-side partial match over encrypted names fast
enough, and how much does GCM cost over the CBC builtin the system uses today.

Two further variants bracket where the GCM query's time goes. Both use the same
predicate, `CHAR_LENGTH(x) > 0`, which is true for every row: `plain_len` over a
plaintext utf8mb4 column (scan, no UDF, no crypto) and `gcm_len` over
`gcm_decrypt(...)`. Same predicate, same rows counted, so `gcm_len - plain_len` is a
difference between two queries that differ only in the decrypting UDF call, and
`gcm - gcm_len` the difference between a LIKE and the length check on the decrypted
result. These are differences of p95 between queries, not component timings: the
script reports them as such. The gate compares `gcm` with `aes` only.

Everything cryptographic happens in the server through SQL. This script only
issues statements, times them, and compares against tests/load/baseline.json
(stack-python rule: JSON on stdout, human summary on stderr, gate via exit code).
"""

# ruff: noqa: S608
# S608 (SQL built from an f-string): the interpolated parts are the module-level
# schema and table constants only; keys and plaintext are bound parameters.

from __future__ import annotations

import argparse
import json
import math
import os
import random
import statistics
import sys
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, dataclass

import pymysql
from pymysql.connections import Connection

# Public fixture key from spec/test-vectors.json — never a real key, and the load
# rows are generated names, never PHI (testing rule). The shorter suites take its
# first 24 or 16 bytes: the key length selects the suite and nothing else does
# (design A10), so a suite here is a key length and a gcm.min_key_bytes setting.
FIXTURE_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
SUITES = {"aes256": 32, "aes192": 24, "aes128": 16}
SCHEMA = "gcm_load"
TABLE = "patients"
IV_HEX = "101112131415161718191a1b1c1d1e1f"

SURNAMES = ("김", "이", "박", "최", "정", "강", "조", "윤", "장", "임")
GIVEN = ("철수", "영희", "길동", "민수", "지훈", "서연", "하늘", "도윤", "예린", "수빈")
NEEDLE = "김"

WARMUP_RUNS = 3
# 40, not 20. p95 of 20 samples is rank 19 of 20 — one sample short of the maximum, so the
# statistic follows whichever single request was unluckiest. Measured across three otherwise
# identical CI runs at one session, the *ratio* of two such numbers ranged 0.809 to 0.928,
# a 1.15x spread on a gate set at 1.05. At 40 the rank is 38, with two samples above it.
# docs/perf.md records what the spread became.
MEASURED_RUNS = 40
INSERT_BATCH = 1000


@dataclass
class Measurement:
    rows: int
    concurrency: int
    variant: str  # plain_len | gcm_len | gcm | aes
    p50_ms: float
    p95_ms: float
    max_ms: float


def connect() -> Connection:
    return pymysql.connect(
        host=os.environ.get("MYSQL_HOST", "127.0.0.1"),
        port=int(os.environ.get("MYSQL_PORT", "3306")),
        user=os.environ.get("MYSQL_USER", "root"),
        password=os.environ.get("MYSQL_PASSWORD", ""),
        charset="utf8mb4",
        autocommit=True,
    )


def execute(conn: Connection, sql: str, args: tuple[object, ...] = ()) -> None:
    with conn.cursor() as cur:
        cur.execute(sql, args)


def scalar(conn: Connection, sql: str, args: tuple[object, ...] = ()) -> object:
    with conn.cursor() as cur:
        cur.execute(sql, args)
        row = cur.fetchone()
    assert row is not None, sql
    return row[0]


def generated_names(count: int, seed: int) -> list[str]:
    """Deterministic name generator: a fixed seed keeps runs comparable."""
    rng = random.Random(seed)  # noqa: S311 - generates load fixture names, not key material
    return [f"{rng.choice(SURNAMES)}{rng.choice(GIVEN)}" for _ in range(count)]


def suite_key_hex(suite: str) -> str:
    return FIXTURE_KEY_HEX[: SUITES[suite] * 2]


@contextmanager
def encryption_floor(conn: Connection, key_bytes: int) -> Iterator[None]:
    """Temporarily lowers the write policy and restores it even if loading fails.

    Only the two encryption functions consult it, so this is needed to *write* the
    AES-192 or AES-128 column; decryption, which is what the measurement times, ignores
    it. GLOBAL on every supported major, so the caller restores the previous value.
    """
    previous = int(str(scalar(conn, "SELECT @@GLOBAL.gcm.min_key_bytes")))
    if previous <= key_bytes:
        # Already permitted by the administrator: nothing to lower, so nothing to
        # restore. Writing the same value twice would only add two statements.
        yield
        return
    execute(conn, "SET GLOBAL gcm.min_key_bytes = %s", (key_bytes,))
    try:
        yield
    finally:
        execute(conn, "SET GLOBAL gcm.min_key_bytes = %s", (previous,))


def load_rows(conn: Connection, rows: int, seed: int, suite: str) -> None:
    """Fills the table with the same plaintext in a GCM, a CBC and a plaintext column.

    The CBC column is written with the builtin AES_ENCRYPT under aes-256-cbc, which
    is exactly the baseline this component has to stay close to. It stays AES-256
    whatever the GCM suite: the question is what each suite costs against the
    builtin a deployment uses today, and keeping the denominator fixed is what makes
    the three suites' ratios comparable with each other.

    The plaintext column carries no collation clause on purpose: it takes the
    charset's default collation, which is also what gcm_decrypt's utf8mb4-tagged
    result gets, so `plain` runs LIKE under the same collation as `gcm`.
    """
    execute(conn, f"CREATE DATABASE IF NOT EXISTS {SCHEMA}")
    execute(conn, f"DROP TABLE IF EXISTS {SCHEMA}.{TABLE}")
    execute(
        conn,
        f"CREATE TABLE {SCHEMA}.{TABLE} ("
        "  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        "  name_gcm VARBINARY(128) NOT NULL,"
        "  name_cbc VARBINARY(128) NOT NULL,"
        "  name_plain VARCHAR(64) CHARACTER SET utf8mb4 NOT NULL"
        ") ENGINE=InnoDB",
    )
    execute(conn, "SET SESSION block_encryption_mode = 'aes-256-cbc'")

    names = generated_names(rows, seed)
    key_hex = suite_key_hex(suite)
    placeholder = "(gcm_encrypt_det(%s, UNHEX(%s)), AES_ENCRYPT(%s, UNHEX(%s), UNHEX(%s)), %s)"
    for start in range(0, rows, INSERT_BATCH):
        batch = names[start : start + INSERT_BATCH]
        values = ", ".join([placeholder] * len(batch))
        args: list[object] = []
        for name in batch:
            args += [name, key_hex, name, FIXTURE_KEY_HEX, IV_HEX, name]
        execute(
            conn,
            f"INSERT INTO {SCHEMA}.{TABLE} (name_gcm, name_cbc, name_plain) VALUES {values}",
            tuple(args),
        )


# The measurement order is not this order: see query_schedule().
QUERIES = {
    # The two controls share one predicate so their difference is the decrypting call and
    # nothing else: CHAR_LENGTH, true for every row, so both count every row.
    "plain_len": f"SELECT COUNT(*) FROM {SCHEMA}.{TABLE} WHERE CHAR_LENGTH(name_plain) > 0",
    "gcm_len": (
        f"SELECT COUNT(*) FROM {SCHEMA}.{TABLE} "
        "WHERE CHAR_LENGTH(gcm_decrypt(name_gcm, UNHEX(%s))) > 0"
    ),
    "gcm": (
        f"SELECT COUNT(*) FROM {SCHEMA}.{TABLE} WHERE gcm_decrypt(name_gcm, UNHEX(%s)) LIKE %s"
    ),
    "aes": (
        f"SELECT COUNT(*) FROM {SCHEMA}.{TABLE} "
        "WHERE AES_DECRYPT(name_cbc, UNHEX(%s), UNHEX(%s)) LIKE %s"
    ),
}


def query_args(variant: str, suite: str) -> tuple[object, ...]:
    if variant == "plain_len":
        return ()
    if variant == "gcm_len":
        return (suite_key_hex(suite),)
    if variant == "gcm":
        return (suite_key_hex(suite), f"%{NEEDLE}%")
    return (FIXTURE_KEY_HEX, IV_HEX, f"%{NEEDLE}%")


def de_bruijn_pairs(k: int) -> list[int]:
    """A cyclic sequence over range(k) in which every ordered pair (a, b) — a == b
    included — appears exactly once as consecutive elements: the de Bruijn sequence
    B(k, 2), length k*k. Each symbol appears k times."""
    sequence: list[int] = []
    a = [0] * (2 * k)

    def db(t: int, p: int) -> None:
        if t > 2:
            if 2 % p == 0:
                sequence.extend(a[1 : p + 1])
            return
        a[t] = a[t - p]
        db(t + 1, p)
        for j in range(a[t - p] + 1, k):
            a[t] = j
            db(t + 1, t)

    db(1, 1)
    return sequence


def query_schedule(variants: list[str], runs: int) -> tuple[str, list[str]]:
    """The order one session issues its measured queries in, and the unmeasured query
    issued just before them.

    Each variant runs `runs` times, and every variant is *preceded* by every variant
    (itself included) the same number of times, so whatever one query warms or evicts
    lands equally on all of them. A rotation by one per round did not do that: it made
    each variant's predecessor almost always the same one. The sequence is B(k, 2)
    repeated; the primer is its last element, which closes the cycle so the first
    measured query has a predecessor like every other.
    """
    k = len(variants)
    if runs % k != 0:
        raise ValueError(f"runs ({runs}) must be a multiple of the variant count ({k})")
    cycle = [variants[i] for i in de_bruijn_pairs(k)]
    sequence = cycle * (runs // k)
    return sequence[-1], sequence


def time_one_session(runs: int, suite: str) -> dict[str, list[float]]:
    """Times every variant on one connection, interleaved.

    Interleaved on purpose. Running every GCM session and then every AES session
    measures two different time windows, so anything that makes the host slow for a
    while — a noisy neighbour on a shared runner, a checkpoint, another job on the same
    machine — lands on one variant and shows up as a ratio. Interleaving puts all of
    them under the same ambient load; query_schedule() balances what precedes each.
    """
    conn = connect()
    try:
        execute(conn, "SET SESSION block_encryption_mode = 'aes-256-cbc'")
        for variant in QUERIES:
            for _ in range(WARMUP_RUNS):
                scalar(conn, QUERIES[variant], query_args(variant, suite))

        primer, sequence = query_schedule(list(QUERIES), runs)
        scalar(conn, QUERIES[primer], query_args(primer, suite))
        timings: dict[str, list[float]] = {variant: [] for variant in QUERIES}
        for variant in sequence:
            started = time.perf_counter()
            scalar(conn, QUERIES[variant], query_args(variant, suite))
            timings[variant].append((time.perf_counter() - started) * 1000.0)
        return timings
    finally:
        conn.close()


def percentile(ordered: list[float], fraction: float) -> float:
    """Nearest-rank percentile: the smallest sample at or above the rank.

    `int(len * 0.95)` is one too high. At 20 samples it evaluates to 20, which after the
    0-based index is the *maximum* — so "p95" at one session was the single worst of 20
    requests, and a 1.05 gate on it would fail whenever one request happened to be 15%
    slow. The rank is ceil(0.95 * n), which is 19 of 20.
    """
    rank = math.ceil(fraction * len(ordered))
    return ordered[min(len(ordered) - 1, max(rank - 1, 0))]


def summarise(rows: int, concurrency: int, variant: str, timings: list[float]) -> Measurement:
    ordered = sorted(timings)
    return Measurement(
        rows=rows,
        concurrency=concurrency,
        variant=variant,
        p50_ms=round(statistics.median(ordered), 3),
        p95_ms=round(percentile(ordered, 0.95), 3),
        max_ms=round(ordered[-1], 3),
    )


def measure(rows: int, concurrency: int, suite: str) -> list[Measurement]:
    """One run at this concurrency, producing a Measurement per variant."""
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(time_one_session, MEASURED_RUNS, suite) for _ in range(concurrency)]
        per_session = [future.result() for future in futures]

    merged: dict[str, list[float]] = {variant: [] for variant in QUERIES}
    for session in per_session:
        for variant, values in session.items():
            merged[variant] += values
    return [summarise(rows, concurrency, variant, merged[variant]) for variant in QUERIES]


def tmp_disk_tables(conn: Connection) -> int:
    return int(str(scalar(conn, "SHOW GLOBAL STATUS LIKE 'Created_tmp_disk_tables'")).split()[-1])


def status_value(conn: Connection, name: str) -> int:
    with conn.cursor() as cur:
        cur.execute("SHOW GLOBAL STATUS LIKE %s", (name,))
        row = cur.fetchone()
    assert row is not None, name
    return int(row[1])


def decompose(rows: int, concurrency: int, by_variant: dict[str, Measurement]) -> dict[str, object]:
    """Differences of p95 between the queries, as a share of the gcm query's p95.

    These are differences between queries, not the execution time of components: a p95
    is a rank statistic of each query's own distribution, and the difference of two is
    not the p95 of anything. They bracket where the time goes; they do not attribute it.
    A negative difference means the gap is inside the noise.
    """
    plain_len = by_variant["plain_len"].p95_ms
    gcm_len = by_variant["gcm_len"].p95_ms
    gcm = by_variant["gcm"].p95_ms
    floor_ms = plain_len
    decrypt_ms = gcm_len - plain_len
    like_ms = gcm - gcm_len

    def share(part: float) -> float | None:
        return round(100.0 * part / gcm, 1) if gcm else None

    return {
        "rows": rows,
        "concurrency": concurrency,
        "plain_len_p95_ms": plain_len,
        "gcm_len_p95_ms": gcm_len,
        "gcm_p95_ms": gcm,
        "floor_p95_ms": round(floor_ms, 3),
        "decrypt_call_p95_diff_ms": round(decrypt_ms, 3),
        "like_vs_len_p95_diff_ms": round(like_ms, 3),
        "floor_pct": share(floor_ms),
        "decrypt_call_p95_diff_pct": share(decrypt_ms),
        "like_vs_len_p95_diff_pct": share(like_ms),
        # The decrypt-call difference over the rows it was measured on — a per-row scale
        # to set beside the core micro-benchmark, not a measured per-row time.
        "decrypt_call_p95_diff_ns_per_row": (
            round(decrypt_ms * 1_000_000.0 / rows, 1) if rows else None
        ),
    }


def gate(comparisons: list[dict[str, object]], baseline_path: str) -> list[str]:
    """Returns the gate violations, empty when the run is within budget."""
    with open(baseline_path, encoding="utf-8") as fh:
        baseline = json.load(fh)
    max_ratio = float(baseline["max_p95_ratio"])
    max_p95_ms = float(baseline["max_p95_ms_at_largest_serial"])

    violations: list[str] = []
    for entry in comparisons:
        ratio = float(str(entry["p95_ratio"]))
        if ratio > max_ratio:
            violations.append(
                f"rows={entry['rows']} c={entry['concurrency']}: p95 ratio {ratio} > {max_ratio}"
            )

    largest = max(int(str(entry["rows"])) for entry in comparisons)
    for entry in comparisons:
        if int(str(entry["rows"])) != largest or int(str(entry["concurrency"])) != 1:
            continue
        if float(str(entry["gcm_p95_ms"])) > max_p95_ms:
            violations.append(
                f"rows={largest} c=1: gcm p95 {entry['gcm_p95_ms']}ms > {max_p95_ms}ms"
            )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=10000)
    parser.add_argument("--concurrency", default="1", help="comma separated session counts")
    parser.add_argument("--baseline", choices=["aes"], default="aes")
    parser.add_argument(
        "--suite",
        choices=sorted(SUITES),
        default="aes256",
        help="GCM suite for the encrypted column; the AES_DECRYPT baseline stays aes-256-cbc",
    )
    parser.add_argument("--gate", help="path to baseline.json; exit 1 when exceeded")
    parser.add_argument("--out", help="write the JSON result here as well as stdout")
    parser.add_argument("--seed", type=int, default=20260928)
    args = parser.parse_args()

    concurrencies = [int(c) for c in args.concurrency.split(",")]

    setup = connect()
    try:
        disk_before = status_value(setup, "Created_tmp_disk_tables")
        # Lowered only for as long as the rows are being written: the measured path is
        # decryption, which ignores the setting, and a server left at 16 after the run
        # would be a weaker server than the one the run found.
        with encryption_floor(setup, SUITES[args.suite]):
            load_rows(setup, args.rows, args.seed, args.suite)
        matching = int(str(scalar(setup, QUERIES["gcm"], query_args("gcm", args.suite))))

        measurements: list[Measurement] = []
        for concurrency in concurrencies:
            measurements += measure(args.rows, concurrency, args.suite)

        disk_after = status_value(setup, "Created_tmp_disk_tables")
        version = str(scalar(setup, "SELECT VERSION()"))
    finally:
        setup.close()

    comparisons: list[dict[str, object]] = []
    decompositions: list[dict[str, object]] = []
    for concurrency in concurrencies:
        by_variant = {m.variant: m for m in measurements if m.concurrency == concurrency}
        gcm = by_variant["gcm"]
        aes = by_variant["aes"]
        decompositions.append(decompose(args.rows, concurrency, by_variant))
        comparisons.append(
            {
                "rows": args.rows,
                "concurrency": concurrency,
                "gcm_p50_ms": gcm.p50_ms,
                "gcm_p95_ms": gcm.p95_ms,
                "aes_p50_ms": aes.p50_ms,
                "aes_p95_ms": aes.p95_ms,
                "p95_ratio": round(gcm.p95_ms / aes.p95_ms, 3) if aes.p95_ms else None,
            }
        )

    result: dict[str, object] = {
        "server_version": version,
        "suite": args.suite,
        "key_bytes": SUITES[args.suite],
        "rows": args.rows,
        "seed": args.seed,
        "needle": NEEDLE,
        "matching_rows": matching,
        "created_tmp_disk_tables_delta": disk_after - disk_before,
        "measurements": [asdict(m) for m in measurements],
        "comparisons": comparisons,
        "decomposition": decompositions,
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)

    for entry in comparisons:
        print(
            f"{args.suite} rows={entry['rows']} c={entry['concurrency']} "
            f"gcm p95={entry['gcm_p95_ms']}ms aes p95={entry['aes_p95_ms']}ms "
            f"ratio={entry['p95_ratio']}",
            file=sys.stderr,
        )
    for entry in decompositions:
        print(
            f"{args.suite} rows={entry['rows']} c={entry['concurrency']} "
            f"plain_len p95={entry['plain_len_p95_ms']}ms gcm_len p95={entry['gcm_len_p95_ms']}ms "
            f"| p95 differences: floor {entry['floor_pct']}% "
            f"decrypt call {entry['decrypt_call_p95_diff_ms']}ms "
            f"({entry['decrypt_call_p95_diff_pct']}%, {entry['decrypt_call_p95_diff_ns_per_row']} "
            f"ns/row) like-vs-len {entry['like_vs_len_p95_diff_ms']}ms "
            f"({entry['like_vs_len_p95_diff_pct']}%)",
            file=sys.stderr,
        )

    if args.gate:
        violations = gate(comparisons, args.gate)
        for violation in violations:
            print(f"GATE {violation}", file=sys.stderr)
        if violations:
            return 1
        print("gate: within budget", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
