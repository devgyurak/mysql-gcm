---
name: dev-container
description: Starting a local docker MySQL development server, installing the component .so, and running the Phase S spike checklist (scripts/dev-up.sh, scripts/verify.sql). Use it when you want to actually run the functions locally.
---

# dev-container

## Starting a server — `scripts/dev-up.sh <8.0|8.4|9>`
The script is the source of truth. Read it rather than repeating it here. Only what matters:

- Images are pinned by digest from `docker/versions.json` (one place mapping major → patch version +
  digest).
- `--loose_gcm.strict=ON` — without `loose_`, starting up before the component is installed fails
  (design §6).
- `--general_log=OFF` as a habit even in development (keys and plaintext in the logs, operational
  constraint §6).
- `--binlog_format=ROW` is an **option removed in 9.0**, so do not pass it when the major is 9 — the
  server will not start.
- The port is `0:3306`, and readiness is a `HEALTHCHECK` poll with a timeout. Never wait with a bare
  `sleep`.

## Installing
`plugin_dir` differs per image (the official OL-based images use `/usr/lib64/mysql/plugin/`). Do not
hardcode it; ask the server, which is what `scripts/verify.sh` does.

```sh
dir=$(docker exec mysql-dev-$ver mysql -uroot -N -e 'SELECT @@plugin_dir')
docker cp build/$ver/component_gcm.so "mysql-dev-$ver:${dir}component_gcm.so"
docker exec -i mysql-dev-$ver mysql -uroot -e "INSTALL COMPONENT 'file://component_gcm'"
```
To reinstall, `UNINSTALL COMPONENT` and then copy. If it is in use the UNINSTALL fails — disconnect the
session.

## The Phase S check — `scripts/verify.sql` (reflecting amendments A1 and A5)
`scripts/verify.sql` is the source of truth. Run it with:

```sh
docker exec -i mysql-dev-$ver mysql -uroot --default-character-set=utf8mb4 -t --force \
  < scripts/verify.sql
```

`--force` is required, because some sections **expect an error**, such as the wrong key length. The key
is the public fixture key from `spec/test-vectors.json` (`0001..1f`). The sections that create a
temporary table need a schema, so `CREATE DATABASE` and `USE` come first.

Record the results in the `docs/design.md` §8 "confirmed / unconfirmed" table **together with the
observed values**. Already measured (8.0.43 · 8.4.11 · 9.4.0): `korean_like=1`,
`CHARSET()=utf8mb4`, case-insensitive LIKE 1, the deterministic envelope byte-matching
`spec/envelope.md` §5.1, a `Created_tmp_disk_tables` increase of 0, and `INSTALL COMPONENT` succeeding
(which means the EVP fetch succeeded). `gcm.strict` is GLOBAL-only on 8.0 and 8.4, so `SET SESSION` is
rejected with 1229 (amendment A5).

## Several versions at once
With the port published as `0:3306` there is no conflict. List them with
`docker ps --filter name=mysql-dev-` and clean up with `docker rm -f mysql-dev-<ver>`.
