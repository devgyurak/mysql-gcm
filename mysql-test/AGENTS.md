# mysql-test/ — MTR suite `gcm`

- `.agents/rules/testing.md` — express GWT with `--echo # Given/When/Then`, and read a `.result`
  through by eye after `--record` before committing it
- The MTR section of the `integration-tests` skill. The suite runs symlinked into a server source tree
  as `suite/gcm`.
- Run it with `scripts/mtr.sh <major>`. The committed `.result` files were recorded **against 8.4**.
  The suite is 8.4-only for now, because the replication cases use `include/rpl/*` (8.4+) and
  `binlog_format=STATEMENT` (removed in 9.0). Behaviour that differs by version is covered by
  `tests/integration`, which runs on 8.0, 8.4 and 9.
