"""SQL helpers shared by the scenarios.

Deliberately thin: it runs statements and returns rows. No cryptography, and no
assertions — a scenario states its own expectations so a failure names the
behaviour that broke.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pymysql

if TYPE_CHECKING:  # avoid a runtime import cycle with the runner
    from runner import Context

REPLICATION_WAIT_SECONDS = 30


def execute(conn: pymysql.connections.Connection, sql: str, args: tuple[object, ...] = ()) -> None:
    with conn.cursor() as cur:
        cur.execute(sql, args or None)


def row(
    conn: pymysql.connections.Connection, sql: str, args: tuple[object, ...] = ()
) -> tuple[object, ...]:
    with conn.cursor() as cur:
        cur.execute(sql, args or None)
        result = cur.fetchone()
    assert result is not None, f"expected one row from: {sql}"
    return tuple(result)


def rows(
    conn: pymysql.connections.Connection, sql: str, args: tuple[object, ...] = ()
) -> list[tuple[object, ...]]:
    with conn.cursor() as cur:
        cur.execute(sql, args or None)
        return [tuple(r) for r in cur.fetchall()]


def error_code(
    conn: pymysql.connections.Connection, sql: str, args: tuple[object, ...] = ()
) -> int:
    """Runs a statement that must fail and returns the MySQL error number.

    Returning 0 for a statement that unexpectedly succeeded lets the scenario
    assert on a number instead of wrapping the call in control flow.
    """
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args or None)
            cur.fetchall()
    except pymysql.MySQLError as exc:
        return int(exc.args[0])
    return 0


def fresh_table(ctx: Context, name: str, definition: str) -> None:
    execute(ctx.primary, f"DROP TABLE IF EXISTS {ctx.schema()}.{name}")
    execute(ctx.primary, f"CREATE TABLE {ctx.schema()}.{name} ({definition})")
    wait_until_replicated(ctx)


def wait_until_replicated(ctx: Context) -> None:
    """Blocks until the replica has applied everything the primary has written.

    GTID based, so there is no sleep and no polling loop (stack-ci-docker rule).
    """
    executed = row(ctx.primary, "SELECT @@GLOBAL.gtid_executed")[0]
    waited = row(
        ctx.replica,
        "SELECT WAIT_FOR_EXECUTED_GTID_SET(%s, %s)",
        (str(executed), REPLICATION_WAIT_SECONDS),
    )[0]
    assert int(str(waited)) == 0, "replica did not catch up within the timeout"
