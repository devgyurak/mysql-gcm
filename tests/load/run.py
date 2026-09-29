#!/usr/bin/env python3
"""Load test: server-side decrypt + LIKE against the AES_DECRYPT baseline.

The question this answers is the one docs/design.md §1.2 raises with estimates
rather than measurements: is a server-side partial match over encrypted names fast
enough, and how much does GCM cost over the CBC builtin the system uses today.

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
import os
import random
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass

import pymysql
from pymysql.connections import Connection

# Public fixture key from spec/test-vectors.json — never a real key, and the load
# rows are generated names, never PHI (testing rule).
FIXTURE_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
SCHEMA = "gcm_load"
TABLE = "patients"
IV_HEX = "101112131415161718191a1b1c1d1e1f"

SURNAMES = ("김", "이", "박", "최", "정", "강", "조", "윤", "장", "임")
GIVEN = ("철수", "영희", "길동", "민수", "지훈", "서연", "하늘", "도윤", "예린", "수빈")
NEEDLE = "김"

WARMUP_RUNS = 3
MEASURED_RUNS = 20
INSERT_BATCH = 1000


@dataclass
class Measurement:
    rows: int
    concurrency: int
    variant: str  # gcm | aes
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


def load_rows(conn: Connection, rows: int, seed: int) -> None:
    """Fills the table with the same plaintext in a GCM and a CBC column.

    The CBC column is written with the builtin AES_ENCRYPT, which is exactly the
    baseline this component has to stay close to.
    """
    execute(conn, f"CREATE DATABASE IF NOT EXISTS {SCHEMA}")
    execute(conn, f"DROP TABLE IF EXISTS {SCHEMA}.{TABLE}")
    execute(
        conn,
        f"CREATE TABLE {SCHEMA}.{TABLE} ("
        "  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        "  name_gcm VARBINARY(128) NOT NULL,"
        "  name_cbc VARBINARY(128) NOT NULL"
        ") ENGINE=InnoDB",
    )
    execute(conn, "SET SESSION block_encryption_mode = 'aes-256-cbc'")

    names = generated_names(rows, seed)
    placeholder = "(gcm_encrypt_det(%s, UNHEX(%s)), AES_ENCRYPT(%s, UNHEX(%s), UNHEX(%s)))"
    for start in range(0, rows, INSERT_BATCH):
        batch = names[start : start + INSERT_BATCH]
        values = ", ".join([placeholder] * len(batch))
        args: list[object] = []
        for name in batch:
            args += [name, FIXTURE_KEY_HEX, name, FIXTURE_KEY_HEX, IV_HEX]
        execute(
            conn,
            f"INSERT INTO {SCHEMA}.{TABLE} (name_gcm, name_cbc) VALUES {values}",
            tuple(args),
        )


QUERIES = {
    "gcm": (
        f"SELECT COUNT(*) FROM {SCHEMA}.{TABLE} WHERE gcm_decrypt(name_gcm, UNHEX(%s)) LIKE %s"
    ),
    "aes": (
        f"SELECT COUNT(*) FROM {SCHEMA}.{TABLE} "
        "WHERE AES_DECRYPT(name_cbc, UNHEX(%s), UNHEX(%s)) LIKE %s"
    ),
}


def query_args(variant: str) -> tuple[object, ...]:
    if variant == "gcm":
        return (FIXTURE_KEY_HEX, f"%{NEEDLE}%")
    return (FIXTURE_KEY_HEX, IV_HEX, f"%{NEEDLE}%")


def time_one_session(runs: int) -> dict[str, list[float]]:
    """Times both variants on one connection, alternating between them.

    Interleaved on purpose. Running every GCM session and then every AES session
    measures two different time windows, so anything that makes the host slow for a
    while — a noisy neighbour on a shared runner, a checkpoint, another job on the same
    machine — lands on one variant and shows up as a ratio. Alternating puts both under
    the same ambient load and the same contention, which is what the ratio is supposed
    to be about.
    """
    conn = connect()
    try:
        execute(conn, "SET SESSION block_encryption_mode = 'aes-256-cbc'")
        for variant in QUERIES:
            for _ in range(WARMUP_RUNS):
                scalar(conn, QUERIES[variant], query_args(variant))

        timings: dict[str, list[float]] = {variant: [] for variant in QUERIES}
        for _ in range(runs):
            for variant in QUERIES:
                started = time.perf_counter()
                scalar(conn, QUERIES[variant], query_args(variant))
                timings[variant].append((time.perf_counter() - started) * 1000.0)
        return timings
    finally:
        conn.close()


def summarise(rows: int, concurrency: int, variant: str, timings: list[float]) -> Measurement:
    ordered = sorted(timings)
    return Measurement(
        rows=rows,
        concurrency=concurrency,
        variant=variant,
        p50_ms=round(statistics.median(ordered), 3),
        p95_ms=round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
        max_ms=round(ordered[-1], 3),
    )


def measure(rows: int, concurrency: int) -> list[Measurement]:
    """One run at this concurrency, producing a Measurement per variant."""
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(time_one_session, MEASURED_RUNS) for _ in range(concurrency)]
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
    parser.add_argument("--gate", help="path to baseline.json; exit 1 when exceeded")
    parser.add_argument("--out", help="write the JSON result here as well as stdout")
    parser.add_argument("--seed", type=int, default=20260928)
    args = parser.parse_args()

    concurrencies = [int(c) for c in args.concurrency.split(",")]

    setup = connect()
    try:
        disk_before = status_value(setup, "Created_tmp_disk_tables")
        load_rows(setup, args.rows, args.seed)
        matching = int(str(scalar(setup, QUERIES["gcm"], query_args("gcm"))))

        measurements: list[Measurement] = []
        for concurrency in concurrencies:
            measurements += measure(args.rows, concurrency)

        disk_after = status_value(setup, "Created_tmp_disk_tables")
        version = str(scalar(setup, "SELECT VERSION()"))
    finally:
        setup.close()

    comparisons: list[dict[str, object]] = []
    for concurrency in concurrencies:
        gcm = next(m for m in measurements if m.concurrency == concurrency and m.variant == "gcm")
        aes = next(m for m in measurements if m.concurrency == concurrency and m.variant == "aes")
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
        "rows": args.rows,
        "seed": args.seed,
        "needle": NEEDLE,
        "matching_rows": matching,
        "created_tmp_disk_tables_delta": disk_after - disk_before,
        "measurements": [asdict(m) for m in measurements],
        "comparisons": comparisons,
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)

    for entry in comparisons:
        print(
            f"rows={entry['rows']} c={entry['concurrency']} "
            f"gcm p95={entry['gcm_p95_ms']}ms aes p95={entry['aes_p95_ms']}ms "
            f"ratio={entry['p95_ratio']}",
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
