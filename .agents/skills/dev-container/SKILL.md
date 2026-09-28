---
name: dev-container
description: 로컬 docker MySQL 개발 서버 기동, component .so 설치, Phase S 스파이크 체크리스트 실행(scripts/dev-up.sh, scripts/verify.sql). 로컬에서 함수를 실제로 돌려볼 때 사용.
---

# dev-container

## 기동 — `scripts/dev-up.sh <8.0|8.4|9>`
스크립트가 원본이다. 여기서 되풀이하지 말고 읽는다. 중요한 점만:

- 이미지는 `docker/versions.json` 의 digest 로 고정한다 (major → 패치 버전 + digest 한 곳).
- `--loose_gcm.strict=ON` — `loose_` 없이는 component 설치 전 기동이 실패한다 (design §6).
- `--general_log=OFF` 는 개발에서도 습관으로 (키·평문이 로그에 남는 운영 제약 §6).
- `--binlog_format=ROW` 는 **9.0 에서 제거된 옵션**이므로 major 가 9 면 넣지 않는다 (넣으면 기동 실패).
- 포트는 `0:3306`, 준비 대기는 `HEALTHCHECK` 폴링 + 타임아웃. 맨 `sleep` 로 기다리지 않는다.

## 설치
`plugin_dir` 은 이미지마다 다르다 (공식 OL 기반 이미지는 `/usr/lib64/mysql/plugin/`). 하드코딩하지 말고
서버에 물어본다 — `scripts/verify.sh` 가 그렇게 한다.

```sh
dir=$(docker exec mysql-dev-$ver mysql -uroot -N -e 'SELECT @@plugin_dir')
docker cp build/$ver/component_gcm.so "mysql-dev-$ver:${dir}component_gcm.so"
docker exec -i mysql-dev-$ver mysql -uroot -e "INSTALL COMPONENT 'file://component_gcm'"
```
재설치는 `UNINSTALL COMPONENT` 후 cp. 사용 중이면 UNINSTALL 이 실패한다 → 세션을 끊는다.

## Phase S 체크 — `scripts/verify.sql` (개정 A1·A5 반영)
`scripts/verify.sql` 이 원본이다. 실행:

```sh
docker exec -i mysql-dev-$ver mysql -uroot --default-character-set=utf8mb4 -t --force \
  < scripts/verify.sql
```

`--force` 가 필요하다 — 키 길이 오류처럼 **에러를 기대하는 절**이 있기 때문이다. 키는
`spec/test-vectors.json` 의 공개 픽스처 키(`0001..1f`)를 쓴다. 임시 테이블을 만드는 절은 스키마가
필요하므로 `CREATE DATABASE` + `USE` 를 먼저 한다.

결과는 `docs/design.md` §8 "확인됨/미확인" 표에 **관측값과 함께** 기록한다. 실측 완료분
(8.0.43 · 8.4.11 · 9.4.0): `korean_like=1`, `CHARSET()=utf8mb4`, 대소문자 무시 LIKE 1,
결정적 봉투가 `spec/envelope.md` §5.1 과 바이트 일치, `Created_tmp_disk_tables` 증가량 0,
`INSTALL COMPONENT` 성공(= EVP fetch 성공). `gcm.strict` 는 8.0·8.4 에서 GLOBAL 전용이라
`SET SESSION` 이 1229 로 거부된다 (개정 A5).

## 여러 버전 동시
포트를 `0:3306` 으로 두어 충돌이 없다. `docker ps --filter name=mysql-dev-` 로 목록, `docker rm -f mysql-dev-<ver>` 로 정리.
