#!/usr/bin/env bash
# Integration smoke: installs the built component into a local MySQL container and
# replays tests/integration/*.sql, diffing stdout against the committed .expected.
#
#   scripts/verify.sh 8.4
#   GCM_RECORD=1 scripts/verify.sh 8.4    # rewrite .expected (review the diff!)
set -euo pipefail

usage() {
  echo "usage: $(basename "$0") <mysql-major>   e.g. 8.0 | 8.4 | 9" >&2
  exit 2
}
[ $# -eq 1 ] || usage
ver="$1"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Must match what scripts/dev-up.sh below creates, including a GCM_DEV_NAME override
# (scripts/verify-nested.sh relies on the same variable).
name="${GCM_DEV_NAME:-mysql-dev-${ver}}"
so="${root}/build/${ver}/component_gcm.so"
outdir="${root}/build/${ver}"

[ -f "${so}" ] || {
  echo "missing ${so} — run scripts/build-in-docker.sh ${ver} first" >&2
  exit 1
}

"${root}/scripts/dev-up.sh" "${ver}" >&2

mysql() { docker exec -i "${name}" mysql -uroot --default-character-set=utf8mb4 "$@"; }

# plugin_dir differs between the official images (/usr/lib64/... on the
# Oracle-Linux based ones), so ask the server instead of hardcoding it.
plugin_dir="$(mysql -N -e "SELECT @@plugin_dir" | tr -d '\r')"
docker cp "${so}" "${name}:${plugin_dir}/component_gcm.so" >/dev/null

# Reinstalling picks up a rebuilt .so; a fresh container has nothing to uninstall.
mysql -N -e "UNINSTALL COMPONENT 'file://component_gcm'" >/dev/null 2>&1 || true
if ! mysql -N -e "INSTALL COMPONENT 'file://component_gcm'"; then
  # The server reports "Cannot load component from specified URN" for a missing file,
  # an unsatisfied service dependency and an already-loaded component alike, so print
  # what would tell them apart rather than leaving the reader guessing.
  echo "INSTALL COMPONENT failed; diagnostics follow" >&2
  mysql -t -e "SELECT * FROM mysql.component" >&2 || true
  docker logs --tail 40 "${name}" >&2 || true
  exit 1
fi

# Cases create tables, so they need a schema. Providing one here keeps the
# boilerplate out of every case file and guarantees a clean slate per run.
schema=gcm_it
mysql -N -e "DROP DATABASE IF EXISTS ${schema}; CREATE DATABASE ${schema}"
# --loose-commands=ON: a case that needs a fresh session uses the client's `connect`
# command (61_kr_key_source does, to pick up a GLOBAL gcm.strict on every major). The
# 9.x client only honours client commands in a batch when asked; the 8.x clients do not
# know the option, hence loose.
case_mysql() {
  docker exec -i "${name}" mysql -uroot --loose-commands=ON --default-character-set=utf8mb4 \
    -D "${schema}" "$@"
}

tmp_disk() { mysql -N -e "SHOW GLOBAL STATUS LIKE 'Created_tmp_disk_tables'" | awk '{print $2}'; }
disk_before="$(tmp_disk)"

# A key a case generated must not be there for the next one, and an aborted run must
# not leave one behind (design A13) — the same reasoning as resetting gcm.strict. Only
# the cases' own keys go: ids starting with it_, stored by the account the cases run
# as. This is a development server and may hold keys for data outside this suite;
# emptying the keyring would leave that data without its key.
drop_case_keys() {
  local key_id
  mysql -N -e "SELECT KEY_ID FROM performance_schema.keyring_keys
               WHERE KEY_ID LIKE 'it\\_%' AND KEY_OWNER = CURRENT_USER()" |
    while IFS= read -r key_id; do
      # </dev/null: the client is `docker exec -i`, which would otherwise read the
      # rest of the list as its own input and end the loop after one key.
      mysql -N -e "DO keyring_key_remove('${key_id}')" </dev/null
    done
}

status=0
shopt -s nullglob
cases=("${root}"/tests/integration/*.sql)
[ ${#cases[@]} -gt 0 ] || { echo "no cases in tests/integration" >&2; exit 1; }

for case_file in "${cases[@]}"; do
  case_name="$(basename "${case_file}" .sql)"
  # A case that declares "per-major-expected" is compared against a per-major file:
  # gcm.strict scope and the 8.x UDF-argument defect genuinely differ by version
  # (docs/design.md amendment A5 and tests/integration/91_*). Everything else must
  # produce identical output on every major.
  if head -3 "${case_file}" | grep -q -- "per-major-expected"; then
    expected="${root}/tests/integration/${case_name}.${ver}.expected"
  else
    expected="${root}/tests/integration/${case_name}.expected"
  fi
  actual="${outdir}/${case_name}.actual"

  # --force: cases assert on errors too, so the client must keep going and the
  # error text must land in the compared output.
  #
  # The streams are captured separately and then concatenated: the client block
  # buffers stdout but not stderr, so a plain 2>&1 interleaves them in an order
  # that depends on buffer boundaries — exactly the kind of flakiness the testing
  # rule forbids. Errors therefore appear in their own section, in statement order.
  # Cases run in sequence against one server and 31_strict_scope touches a GLOBAL
  # variable, so the default is restored before each case: order independence should
  # not depend on a case cleaning up after itself.
  mysql -N -e "SET GLOBAL gcm.strict = DEFAULT"
  drop_case_keys
  case_mysql -N --force < "${case_file}" > "${actual}.out" 2> "${actual}.err" || true
  {
    cat "${actual}.out"
    if [ -s "${actual}.err" ]; then
      echo "--- errors, in statement order ---"
      cat "${actual}.err"
    fi
  } > "${actual}"
  rm -f "${actual}.out" "${actual}.err"

  if [ "${GCM_RECORD:-0}" = "1" ]; then
    cp "${actual}" "${expected}"
    echo "recorded $(basename "${expected}")" >&2
    continue
  fi

  if [ ! -f "${expected}" ]; then
    echo "FAIL ${case_name}: no ${case_name}.expected (GCM_RECORD=1 to create)" >&2
    status=1
    continue
  fi

  if diff -u "${expected}" "${actual}"; then
    echo "ok   ${case_name}" >&2
  else
    echo "FAIL ${case_name}" >&2
    status=1
  fi
done

disk_after="$(tmp_disk)"
{
  echo "mysql_major=${ver}"
  echo "created_tmp_disk_tables_before=${disk_before}"
  echo "created_tmp_disk_tables_after=${disk_after}"
  echo "created_tmp_disk_tables_delta=$((disk_after - disk_before))"
} > "${outdir}/tmp_disk.txt"
cat "${outdir}/tmp_disk.txt" >&2

drop_case_keys
mysql -N -e "DROP DATABASE IF EXISTS ${schema}"
mysql -N -e "UNINSTALL COMPONENT 'file://component_gcm'"

exit "${status}"
