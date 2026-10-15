#!/usr/bin/env python3
"""Study harness beside the gated load runner: which SQL recipe reduces the work a
`gcm_decrypt(...) LIKE` query does, and what plan the optimizer chooses for each.

Not a gate, and `tests/load/run.py` is not touched. Per recipe it records the filter
node and its child iterator from `EXPLAIN ANALYZE`, the rows **into** the filter, the
match count, the latency, and the buffer-pool, table and index sizes at the run.
**The rows into the filter are not the rows decrypted**: a filter with a preceding
conjunct short-circuits the UDF, so the filter node line is recorded beside them.

Recipes run **alone** — each is warmed and measured in its own pass, so a full scan in
one recipe is not measured against another's. That is the opposite of `run.py`, whose
variants are interleaved on purpose to produce a ratio. Everything cryptographic
happens in the server through SQL; the fixture names are generated, never PHI, and the
key is the public fixture key. It prints JSON on stdout with a human summary on stderr
(stack-python rule). Not shipped, and not a client.
"""

# ruff: noqa: S608
# S608 (SQL built from an f-string): the interpolated parts are the module-level
# schema/table/index constants and placeholder counts; keys, plaintext and values
# are bound parameters.

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import cast

from pymysql.connections import Connection
from run import FIXTURE_KEY_HEX, connect, execute, generated_names, percentile, scalar

SCHEMA = "gcm_recipes"
TABLE = "patients"
TABLE_REF = f"{SCHEMA}.{TABLE}"
# The two index shapes the recipes compare. `ix_scope_enc` cannot serve an ORDER BY id
# inside the scope (it is ordered by envelope bytes), so the plan reads the wide row per
# scanned row or decrypts the whole scope and sorts — not a decryption-count difference.
INDEXES = {
    "none": [],
    "scope_enc": ["KEY ix_scope_enc (dept_id, name_enc)"],
    "covering": ["KEY ix_scope_id_enc (dept_id, id, name_enc)"],
    "both": ["KEY ix_scope_enc (dept_id, name_enc)", "KEY ix_scope_id_enc (dept_id, id, name_enc)"],
}
WARMUP_RUNS = 3
MEASURED_RUNS = 20
NEEDLE = "김"
# The padding value is the scope id in eight digits, and `ljust` never truncates, so
# the column cannot be narrower than that whatever `--pad-bytes` says.
PAD_MIN = 8


def pad_value(dept: int, pad_bytes: int) -> str:
    """A fixed-width padding value for a row, at least PAD_MIN bytes wide."""
    return f"{dept:08d}".ljust(max(pad_bytes, PAD_MIN), "0")


@dataclass
class Context:
    """Everything a recipe's SQL needs that is not a bound parameter of the call."""

    needle: str
    dept: int
    chunk: int
    limit: int
    cursor: int

    @property
    def pattern(self) -> str:
        return f"%{self.needle}%"


@dataclass(frozen=True)
class Statement:
    sql: str
    args: tuple[object, ...] = ()
    # True when the statement returns a single COUNT(*) row rather than the matched rows.
    aggregate: bool = False


@dataclass
class Measurement:
    rows: int
    recipe: str
    p50_ms: float
    p95_ms: float
    max_ms: float
    matches: int
    rows_into_filter: int | None
    filter_node: str
    filter_child: str


def _gcm(column: str = "name_enc") -> str:
    return f"gcm_decrypt({column}, UNHEX(%s))"


def recipe_scan(ctx: Context) -> list[Statement]:
    return [
        Statement(
            f"SELECT COUNT(*) FROM {TABLE_REF} WHERE {_gcm()} LIKE %s",
            (FIXTURE_KEY_HEX, ctx.pattern),
            aggregate=True,
        )
    ]


def recipe_scope(ctx: Context) -> list[Statement]:
    return [
        Statement(
            f"SELECT COUNT(*) FROM {TABLE_REF} WHERE dept_id = %s AND {_gcm()} LIKE %s",
            (ctx.dept, FIXTURE_KEY_HEX, ctx.pattern),
            aggregate=True,
        )
    ]


def recipe_newest_first(ctx: Context) -> list[Statement]:
    return [
        Statement(
            f"SELECT id FROM {TABLE_REF} WHERE {_gcm()} LIKE %s ORDER BY id DESC LIMIT %s",
            (FIXTURE_KEY_HEX, ctx.pattern, ctx.limit),
        )
    ]


def recipe_window(ctx: Context) -> list[Statement]:
    lower, upper = window_bounds(ctx.cursor, ctx.chunk)
    return [
        Statement(
            f"SELECT id FROM {TABLE_REF} WHERE id < %s AND id >= %s AND {_gcm()} LIKE %s"
            " ORDER BY id DESC LIMIT %s",
            (upper, lower, FIXTURE_KEY_HEX, ctx.pattern, ctx.limit),
        )
    ]


def recipe_scope_page(ctx: Context) -> list[Statement]:
    """Recipe 2's shape: an ordered page *inside* a scope, which the index shape decides."""
    return [
        Statement(
            f"SELECT id FROM {TABLE_REF} WHERE dept_id = %s AND {_gcm()} LIKE %s"
            " ORDER BY id DESC LIMIT %s",
            (ctx.dept, FIXTURE_KEY_HEX, ctx.pattern, ctx.limit),
        )
    ]


def recipe_wide_read(ctx: Context) -> list[Statement]:
    """The single step of recipe 2: the wide row is read only where the UDF matches."""
    return [
        Statement(
            f"SELECT id, pad FROM {TABLE_REF} WHERE dept_id = %s AND {_gcm()} LIKE %s",
            (ctx.dept, FIXTURE_KEY_HEX, ctx.pattern),
        )
    ]


RECIPES: dict[str, Callable[[Context], list[Statement]]] = {
    "scan": recipe_scan,
    "scope": recipe_scope,
    "scope_page": recipe_scope_page,
    "newest_first": recipe_newest_first,
    "window": recipe_window,
    "wide_read": recipe_wide_read,
}


def rows_into_filter(plan: str) -> tuple[int | None, str, str]:
    """The rows into the `gcm_decrypt` filter, its node line, and the child iterator line.

    `EXPLAIN ANALYZE` prints the filter as a node whose *child's* actual rows are the rows
    that reached it. That is the rows decrypted only when the UDF is the filter's only
    condition: with a conjunct before it (a scope predicate, a range) the server
    short-circuits and decrypts fewer, so the rows into the filter overstate the work and
    must be read beside the node line. Under index condition pushdown there is no filter
    node at all (the condition is inside the index read), so all three are absent.
    """
    lines = plan.splitlines()
    for i, line in enumerate(lines):
        if "gcm_decrypt" not in line or "Filter:" not in line:
            continue
        for child in lines[i + 1 :]:
            match = re.search(r"actual time=[\d.]+\.\.[\d.]+ rows=(\d+)", child)
            if match:
                return int(match.group(1)), line.strip(), child.strip()
        return None, line.strip(), ""
    return None, "", ""


def window_bounds(cursor: int, chunk: int) -> tuple[int, int]:
    """The (inclusive lower, exclusive upper) id window of recipe 3's cursor page."""
    return max(cursor - chunk, 0), cursor


def load_rows(conn: Connection, rows: int, depts: int, pad_bytes: int, seed: int) -> None:
    """A scope column and a wide padding column; names are generated, never PHI."""
    execute(conn, f"CREATE DATABASE IF NOT EXISTS {SCHEMA}")
    execute(conn, f"DROP TABLE IF EXISTS {SCHEMA}.{TABLE}")
    execute(
        conn,
        f"CREATE TABLE {SCHEMA}.{TABLE} ("
        "  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        "  dept_id INT NOT NULL,"
        "  name_enc VARBINARY(128) NOT NULL,"
        f"  pad VARBINARY({len(pad_value(0, pad_bytes))}) NOT NULL"
        ") ENGINE=InnoDB",
    )
    names = generated_names(rows, seed)
    placeholders = "(%s, gcm_encrypt_det(%s, UNHEX(%s)), %s)"
    for start in range(0, rows, 1000):
        batch = names[start : start + 1000]
        values = ", ".join([placeholders] * len(batch))
        args: list[object] = []
        for offset, name in enumerate(batch):
            dept = (start + offset) % depts
            args += [dept, name, FIXTURE_KEY_HEX, pad_value(dept, pad_bytes)]
        execute(
            conn,
            f"INSERT INTO {SCHEMA}.{TABLE} (dept_id, name_enc, pad) VALUES {values}",
            tuple(args),
        )


def add_index(conn: Connection, index: str) -> None:
    for definition in INDEXES[index]:
        execute(conn, f"ALTER TABLE {SCHEMA}.{TABLE} ADD {definition}")


def sizes(conn: Connection) -> dict[str, int]:
    return {
        "innodb_buffer_pool_bytes": int(
            str(scalar(conn, "SELECT @@GLOBAL.innodb_buffer_pool_size"))
        ),
        "table_data_bytes": int(
            str(
                scalar(
                    conn,
                    "SELECT COALESCE(SUM(data_length), 0) FROM information_schema.tables"
                    " WHERE table_schema = %s AND table_name = %s",
                    (SCHEMA, TABLE),
                )
            )
        ),
        "table_index_bytes": int(
            str(
                scalar(
                    conn,
                    "SELECT COALESCE(SUM(index_length), 0) FROM information_schema.tables"
                    " WHERE table_schema = %s AND table_name = %s",
                    (SCHEMA, TABLE),
                )
            )
        ),
    }


def matches_of(statements: list[Statement], result: object) -> int:
    if statements[-1].aggregate:
        return int(str(result))
    return len(cast(list[tuple[object, ...]], result))


def run_statements(conn: Connection, statements: list[Statement]) -> object:
    """Runs the recipe's statements in order and returns the last statement's result."""
    result: object = None
    for statement in statements:
        with conn.cursor() as cur:
            cur.execute(statement.sql, statement.args)
            rows = cur.fetchall()
        result = rows[0][0] if statement.aggregate else rows
    return result


def explain(conn: Connection, statements: list[Statement]) -> tuple[int | None, str, str]:
    plan = str(scalar(conn, f"EXPLAIN ANALYZE {statements[0].sql}", statements[0].args))
    return rows_into_filter(plan)


def measure_recipe(conn: Connection, name: str, ctx: Context, rows: int, runs: int) -> Measurement:
    statements = RECIPES[name](ctx)
    rows_into_filter_count, filter_node, filter_child = explain(conn, statements)
    for _ in range(WARMUP_RUNS):
        run_statements(conn, statements)
    timings: list[float] = []
    result: object = None
    for _ in range(runs):
        started = time.perf_counter()
        result = run_statements(conn, statements)
        timings.append((time.perf_counter() - started) * 1000.0)
    ordered = sorted(timings)
    return Measurement(
        rows=rows,
        recipe=name,
        p50_ms=round(ordered[len(ordered) // 2], 3),
        p95_ms=round(percentile(ordered, 0.95), 3),
        max_ms=round(ordered[-1], 3),
        matches=matches_of(statements, result),
        rows_into_filter=rows_into_filter_count,
        filter_node=filter_node,
        filter_child=filter_child,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=300000)
    parser.add_argument("--depts", type=int, default=100)
    parser.add_argument("--pad-bytes", type=int, default=0, help="width of the non-indexed column")
    parser.add_argument("--needle", default=NEEDLE)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--chunk", type=int, default=20000)
    parser.add_argument("--dept", type=int, default=0)
    parser.add_argument("--index", choices=sorted(INDEXES), default="none")
    parser.add_argument("--recipes", default=",".join(RECIPES))
    parser.add_argument("--runs", type=int, default=MEASURED_RUNS)
    parser.add_argument("--seed", type=int, default=20260928)
    parser.add_argument("--out", help="write the JSON result here as well as stdout")
    args = parser.parse_args()

    names = [name for name in args.recipes.split(",") if name]
    unknown = [name for name in names if name not in RECIPES]
    if unknown:
        parser.error(f"unknown recipe(s) {', '.join(unknown)}; choose from {', '.join(RECIPES)}")

    conn = connect()
    try:
        load_rows(conn, args.rows, args.depts, args.pad_bytes, args.seed)
        add_index(conn, args.index)
        maximum = int(str(scalar(conn, f"SELECT MAX(id) FROM {SCHEMA}.{TABLE}")))
        ctx = Context(
            needle=args.needle,
            dept=args.dept,
            chunk=args.chunk,
            limit=args.limit,
            cursor=maximum + 1,
        )
        measurements = [measure_recipe(conn, name, ctx, args.rows, args.runs) for name in names]
        size_stats = sizes(conn)
        version = str(scalar(conn, "SELECT VERSION()"))
    finally:
        conn.close()

    result = {
        "server_version": version,
        "rows": args.rows,
        "depts": args.depts,
        "pad_bytes": args.pad_bytes,
        "seed": args.seed,
        "needle": args.needle,
        "limit": args.limit,
        "chunk": args.chunk,
        "dept": args.dept,
        "index": args.index,
        "recipes_run": names,
        **size_stats,
        "measurements": [asdict(m) for m in measurements],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
    for m in measurements:
        print(
            f"{m.recipe} p50={m.p50_ms}ms p95={m.p95_ms}ms matches={m.matches} "
            f"rows_into_filter={m.rows_into_filter}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
