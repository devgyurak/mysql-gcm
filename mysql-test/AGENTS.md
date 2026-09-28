# mysql-test/ — MTR suite `gcm`

- `.agents/rules/testing.md` — GWT 는 `--echo # Given/When/Then` 으로, `.result` 는 `--record` 후 눈으로 검토
- 스킬 `integration-tests` 의 MTR 절. 서버 소스 트리에 `suite/gcm` 으로 심링크되어 실행된다.
- 실행은 `scripts/mtr.sh <major>`. 커밋된 `.result` 는 **8.4 기준**으로 `--record` 한 것이다. 복제 케이스가
  `include/rpl/*`(8.4+)와 `binlog_format=STATEMENT`(9.0 에서 제거됨)를 쓰므로 스위트는 현재 8.4 전용이다.
  버전별로 갈리는 동작은 `tests/integration` 이 8.0·8.4·9 세 버전에서 커버한다.
