#!/usr/bin/env bash
# Server test for the server defect of issue #43: a prepared statement whose
# re-prepare at `EXECUTE` fails *after* a loadable function has been fixed abandons that function's
# `UDF_INIT` — its `deinit` is never called, and `UNINSTALL COMPONENT` is refused
# until the server restarts. The first shape found, and the one the issue was filed
# with, is a function that is the argument of another and takes a prepared-statement
# parameter: the inner call is evaluated while the outer function is being
# initialised, before the parameter has a value, and raises. Nesting, the parameter
# and the error are incidental — a sibling function, a key-id function that raises
# nothing, and a re-prepare invalidated by `ALTER TABLE` leak the same way (cases 23
# to 26). The cause is read in docs/upstream-udf-handler-leak.md.
#
#   scripts/verify-nested.sh 8.4
#   GCM_RECORD=1 scripts/verify-nested.sh 8.4    # rewrite .expected (review the diff!)
#
# Why a script of its own, and not a case in scripts/verify.sh: a case that
# triggers the defect leaves the server unable to uninstall the component for every
# case after it. This runs on a *throwaway* container (started and removed here),
# and between cases it either reinstalls the component or, when the uninstall was
# refused, restarts the server and lets the component come back at startup. That
# branching lives here, never in a case body — a case is only SQL.
#
# The keyring setup is the development one, reused through GCM_DEV_NAME so the
# `_kr` shapes (which need a key by id) work, without touching the development
# container scripts/dev-up.sh would otherwise start.
#
# The probe component in tests/probe is installed alongside, so a case can print
# how many `init`s a leaked `UDF_INIT` produced against how many `deinit`s the
# server ever ran. Every case resets the probe's counters first, so the numbers do
# not depend on how many times a previous case forced a restart.
set -euo pipefail

usage() {
  echo "usage: $(basename "$0") <mysql-major>   e.g. 8.0 | 8.4 | 9" >&2
  exit 2
}
[ $# -eq 1 ] || usage
ver="$1"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
name="mysql-nested-${ver}"
outdir="${root}/build/${ver}"
so_gcm="${outdir}/component_gcm.so"
so_probe="${outdir}/component_probe.so"

for so in "${so_gcm}" "${so_probe}"; do
  [ -f "${so}" ] || {
    echo "missing ${so} — run scripts/build-in-docker.sh ${ver} and scripts/build-probe.sh ${ver} first" >&2
    exit 1
  }
done

cleanup() {
  # The CI diagnostics step runs after this trap has removed the container, and it reads
  # mysql-dev-<ver>, not this container's name — so the log has to be taken here.
  if docker container inspect "${name}" >/dev/null 2>&1; then
    docker logs --tail 200 "${name}" > "${outdir}/nested_server.log" 2>&1 || true
  fi
  docker rm -f -v "${name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

# Reuse the development setup — keyring component and keyring_udf — on our own
# container name, so we install and remove it without disturbing anyone.
GCM_DEV_NAME="${name}" "${root}/scripts/dev-up.sh" "${ver}" >&2

mysql() { docker exec -i "${name}" mysql -uroot --default-character-set=utf8mb4 "$@"; }

wait_healthy() {
  local deadline=$((SECONDS + 300))
  while [ "$(docker inspect -f '{{.State.Health.Status}}' "${name}")" != healthy ]; do
    if [ "${SECONDS}" -ge "${deadline}" ]; then
      echo "${name} did not become healthy; last log lines:" >&2
      docker logs --tail 40 "${name}" >&2
      exit 1
    fi
    sleep 2
  done
  local probe_deadline=$((SECONDS + 120))
  until mysql -N -e 'SELECT 1' >/dev/null 2>&1 </dev/null; do
    if [ "${SECONDS}" -ge "${probe_deadline}" ]; then
      echo "${name} is healthy but not answering queries; last log lines:" >&2
      docker logs --tail 40 "${name}" >&2
      exit 1
    fi
    sleep 1
  done
}
wait_healthy

plugin_dir="$(mysql -N -e 'SELECT @@plugin_dir' </dev/null | tr -d '\r')"
docker cp "${so_gcm}" "${name}:${plugin_dir}/component_gcm.so" >/dev/null
docker cp "${so_probe}" "${name}:${plugin_dir}/component_probe.so" >/dev/null
mysql -N -e 'DROP DATABASE IF EXISTS gcm_it; CREATE DATABASE gcm_it' </dev/null

case_mysql() {
  docker exec -i "${name}" mysql -uroot --loose-commands=ON --default-character-set=utf8mb4 \
    -D gcm_it "$@"
}

component_present() {
  [ "$(mysql -N -e "SELECT COUNT(*) FROM mysql.component
                     WHERE component_urn = 'file://component_$1'" </dev/null)" = 1 ]
}

# A component installed by a previous case, or reloaded at server start after a
# restart, is already there; only a first install, or one after a successful
# uninstall, needs the statement.
ensure_installed() {
  component_present "$1" && return 0
  mysql -N -e "INSTALL COMPONENT 'file://component_$1'" </dev/null
}

# A key a case generated must not be there for the next one, and an aborted run must
# not leave one behind — the same reasoning as scripts/verify.sh. Only the cases' own
# ids go: starting with it_, stored by the account the cases run as.
drop_case_keys() {
  local key_id
  mysql -N -e "SELECT KEY_ID FROM performance_schema.keyring_keys
               WHERE KEY_ID LIKE 'it\\_%' AND KEY_OWNER = CURRENT_USER()" </dev/null |
    while IFS= read -r key_id; do
      mysql -N -e "DO keyring_key_remove('${key_id}')" </dev/null
    done
}

status=0
shopt -s nullglob
cases=("${root}"/tests/integration/nested/*.sql)
[ ${#cases[@]} -gt 0 ] || { echo "no cases in tests/integration/nested" >&2; exit 1; }

for case_file in "${cases[@]}"; do
  case_name="$(basename "${case_file}" .sql)"
  # Every case is compared per major: whether the defect reproduces, and what the
  # server does around it, legitimately differ between 8.0, 8.4 and 9.x.
  expected="${root}/tests/integration/nested/${case_name}.${ver}.expected"
  actual="${outdir}/nested_${case_name}.actual"

  # Which component the case leaves unable to uninstall, and therefore which one the
  # after-block below has to uninstall and, if refused, restart the server for.
  component="$(sed -n 's/^-- nested-uninstall: *\([a-z_]*\).*/\1/p' "${case_file}" | head -1)"
  component="${component:-gcm}"

  ensure_installed gcm
  ensure_installed probe
  mysql -N -e 'SELECT probe_reset()' >/dev/null </dev/null
  mysql -N -e 'SET GLOBAL gcm.strict = DEFAULT' </dev/null
  drop_case_keys

  # --force so the case's expected errors do not stop the client; streams captured
  # separately and joined, as in scripts/verify.sh, because stdout is block buffered
  # and stderr is not.
  case_mysql -N --force < "${case_file}" > "${actual}.out" 2> "${actual}.err" || true
  {
    cat "${actual}.out"
    if [ -s "${actual}.err" ]; then
      echo "--- errors, in statement order ---"
      cat "${actual}.err"
    fi
    echo "--- after the case ---"
    printf 'probe_counts: '
    mysql -N -e 'SELECT probe_counts()' </dev/null
    if uninstall_out="$(mysql -N -e "UNINSTALL COMPONENT 'file://component_${component}'" 2>&1 </dev/null)"; then
      echo "uninstall ${component}: ok"
      # The next case needs it back.
      if install_out="$(mysql -N -e "INSTALL COMPONENT 'file://component_${component}'" 2>&1 </dev/null)"; then
        echo "install ${component}: ok"
      else
        echo "install ${component}: failed: ${install_out}"
      fi
    else
      echo "uninstall ${component}: refused: ${uninstall_out}"
      # A function of that component is still referenced. Only a restart releases
      # it, and at startup the server loads what mysql.component still lists.
      docker restart "${name}" >/dev/null
      wait_healthy
      echo "restarted: ${component} re-loaded at server start"
    fi
  } > "${actual}"
  rm -f "${actual}.out" "${actual}.err"

  if [ "${GCM_RECORD:-0}" = "1" ]; then
    cp "${actual}" "${expected}"
    echo "recorded $(basename "${expected}")" >&2
    continue
  fi

  if [ ! -f "${expected}" ]; then
    echo "FAIL nested/${case_name}: no ${case_name}.${ver}.expected (GCM_RECORD=1 to create)" >&2
    status=1
    continue
  fi

  if diff -u "${expected}" "${actual}"; then
    echo "ok   nested/${case_name}" >&2
  else
    echo "FAIL nested/${case_name}" >&2
    status=1
  fi
done

exit "${status}"
