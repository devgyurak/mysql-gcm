"""E2E runner: sets up a primary/replica pair with the component installed, then
executes every scenario against it.

The runner only issues SQL. All encryption and decryption happens inside the
server through gcm_encrypt / gcm_encrypt_det / gcm_decrypt (docs/design.md
amendment A4), so this file contains no cryptography and no test assertions —
those live in scenarios/.
"""

from __future__ import annotations

import importlib
import os
import sys
import time
import traceback
from dataclasses import dataclass

import pymysql
from pymysql.connections import Connection

# Public fixture key from spec/test-vectors.json. Never a real key; it exists so
# the scenarios have something to pass as the SQL key argument.
FIXTURE_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

COMPONENT_URN = "file://component_gcm"
SCHEMA = "gcm_e2e"
REPL_USER = "repl"
# Credentials come from the environment, never from source (stack-python rule). The
# compose file sets this for the throwaway replication user on its private network.
REPL_PASSWORD = os.environ["REPL_PASSWORD"]

# Scenarios that hold on every supported server major.
COMMON_SCENARIOS = (
    "sql_roundtrip",
    "sql_write_like",
    "replica_consistency",
    "dual_read_v1",
    "aad_mismatch",
    "cross_shard_determinism",
)
# gcm.strict gained session scope in MySQL 9.0.0 (docs/design.md amendment A5), so
# the isolation scenario is version-specific. The runner picks one — the scenario
# bodies stay branch-free (testing rule).
SESSION_SCOPE_SCENARIO = "strict_scope_session"
GLOBAL_SCOPE_SCENARIO = "strict_scope_global"
SESSION_SYSVAR_MIN_VERSION = (9, 0, 0)


@dataclass
class Context:
    """What a scenario is handed: connections and the fixture key.

    `primary2` is a *second session on the primary*, not a second server. Session
    isolation of gcm.strict can only be shown with two sessions on one server; using
    the replica for that would pass even if session scope did not work at all.

    `shard_b` is an independent server sharing no binlog with the primary, so the
    cross-shard scenario is about two servers computing the same bytes rather than
    one copying them from the other.
    """

    primary: Connection
    primary2: Connection
    replica: Connection
    shard_b: Connection
    key_hex: str
    server_version: tuple[int, ...]

    def schema(self) -> str:
        return SCHEMA


def connect(host: str) -> Connection:
    return pymysql.connect(
        host=host,
        user=os.environ.get("MYSQL_USER", "root"),
        password=os.environ.get("MYSQL_PASSWORD", ""),
        charset="utf8mb4",
        autocommit=True,
    )


def wait_for(host: str, timeout_s: int = 120) -> Connection:
    deadline = time.monotonic() + timeout_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return connect(host)
        except pymysql.Error as exc:  # server still starting
            last = exc
            time.sleep(1)
    raise RuntimeError(f"{host} never accepted connections: {last}")


def execute(conn: Connection, sql: str, args: tuple[object, ...] = ()) -> None:
    with conn.cursor() as cur:
        # `args or None` so a statement with no parameters skips the driver's
        # %-formatting, where a literal % (as in a 'user'@'%' host) would be read as
        # a placeholder.
        cur.execute(sql, args or None)


def server_version(conn: Connection) -> tuple[int, ...]:
    with conn.cursor() as cur:
        cur.execute("SELECT VERSION()")
        row = cur.fetchone()
    assert row is not None
    text = str(row[0]).split("-", 1)[0]
    return tuple(int(part) for part in text.split("."))


def install_component(conn: Connection) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM mysql.component WHERE component_urn = %s", (COMPONENT_URN,)
        )
        row = cur.fetchone()
    assert row is not None
    if int(row[0]) == 0:
        execute(conn, f"INSTALL COMPONENT '{COMPONENT_URN}'")


def start_replication(primary: Connection, replica: Connection) -> None:
    # This one does carry a parameter, so the wildcard host needs %% for the formatter.
    execute(
        primary,
        f"CREATE USER IF NOT EXISTS '{REPL_USER}'@'%%' IDENTIFIED BY %s",
        (REPL_PASSWORD,),
    )
    execute(primary, f"GRANT REPLICATION SLAVE ON *.* TO '{REPL_USER}'@'%'")

    with replica.cursor() as cur:
        cur.execute("SHOW REPLICA STATUS")
        already = cur.fetchone() is not None
    if already:
        return

    execute(replica, "STOP REPLICA")
    execute(
        replica,
        "CHANGE REPLICATION SOURCE TO SOURCE_HOST='primary', SOURCE_USER=%s, "
        "SOURCE_PASSWORD=%s, SOURCE_AUTO_POSITION=1, GET_SOURCE_PUBLIC_KEY=1",
        (REPL_USER, REPL_PASSWORD),
    )
    execute(replica, "START REPLICA")


def wait_for_replica(primary: Connection, replica: Connection, timeout_s: int = 60) -> None:
    """Blocks until the replica has applied everything the primary has written.

    GTID based, so there is no sleep and no polling loop.
    """
    with primary.cursor() as cur:
        cur.execute("SELECT @@GLOBAL.gtid_executed")
        executed = cur.fetchone()
    assert executed is not None
    with replica.cursor() as cur:
        cur.execute("SELECT WAIT_FOR_EXECUTED_GTID_SET(%s, %s)", (str(executed[0]), timeout_s))
        waited = cur.fetchone()
    assert waited is not None
    assert int(str(waited[0])) == 0, "replica did not catch up within the timeout"


def scenario_names(version: tuple[int, ...]) -> tuple[str, ...]:
    scope = (
        SESSION_SCOPE_SCENARIO if version >= SESSION_SYSVAR_MIN_VERSION else GLOBAL_SCOPE_SCENARIO
    )
    return COMMON_SCENARIOS + (scope,)


def main() -> int:
    primary_host = os.environ.get("PRIMARY_HOST", "primary")
    primary = wait_for(primary_host)
    primary2 = wait_for(primary_host)
    replica = wait_for(os.environ.get("REPLICA_HOST", "replica"))
    shard_b = wait_for(os.environ.get("SHARD_B_HOST", "shard_b"))

    install_component(primary)
    install_component(replica)
    install_component(shard_b)
    start_replication(primary, replica)

    # Created once on the primary and replicated; the replica must have applied it
    # before anything switches into it.
    execute(primary, f"CREATE DATABASE IF NOT EXISTS {SCHEMA}")
    wait_for_replica(primary, replica)
    # shard_b is independent, so it needs its own schema rather than a replicated one.
    execute(shard_b, f"CREATE DATABASE IF NOT EXISTS {SCHEMA}")
    for conn in (primary, primary2, replica, shard_b):
        execute(conn, f"USE {SCHEMA}")

    version = server_version(primary)
    ctx = Context(
        primary=primary,
        primary2=primary2,
        replica=replica,
        shard_b=shard_b,
        key_hex=FIXTURE_KEY_HEX,
        server_version=version,
    )

    print(f"server {'.'.join(str(p) for p in version)}", file=sys.stderr)

    failures: list[str] = []
    for name in scenario_names(version):
        module = importlib.import_module(f"scenarios.{name}")
        try:
            module.run(ctx)
        except Exception:  # a scenario failure must not stop the others
            failures.append(name)
            print(f"FAIL {name}", file=sys.stderr)
            traceback.print_exc()
        else:
            print(f"ok   {name}", file=sys.stderr)

    if failures:
        print(f"{len(failures)} scenario(s) failed: {', '.join(failures)}", file=sys.stderr)
        return 1
    print("all scenarios passed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
