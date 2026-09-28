---
paths:
  - "scripts/**/*.py"
  - "tests/e2e/**/*.py"
  - "tests/load/**/*.py"
  - "**/*.py"
---
<!-- Generated from .agents/rules/stack-python.md by scripts/agents-sync.py — edit the source. -->
# Python 관례

- 3.10+, 의존성 최소. Python 은 내부 개발 도구와 SQL 테스트 runner 에만 사용한다. 배포용 암호화 패키지를 만들지 않는다.
- 벡터 생성 의존성은 `scripts/requirements.txt` 의 `cryptography`. SQL E2E/부하 runner 는 `PyMySQL` 로 통일하고 암복호화는 서버 SQL 함수로 수행한다.
- `ruff` (lint + format), `mypy --strict`. CI 강제. `# type: ignore` 는 사유 주석 필수.
- 공개 encrypt/decrypt/parse API 를 제공하지 않는다. 벡터 생성에 필요한 최소 암호 구성만 스크립트 내부에 두고 `cryptography` 의 프리미티브를 사용한다.
- `scripts/gen-vectors.py --check` 로 출력 재현성을 검사한다. 봉투 오류·태그 실패·왕복은 C++ 단위 및 SQL 통합 테스트에서 검증한다.
- 부하/E2E 스크립트: `argparse`, 결과는 JSON stdout, 사람용 요약은 stderr. 임계값 비교는 스크립트가 exit code 로 알린다 (CI 게이트).
- DB 접속 정보는 환경변수(`MYSQL_HOST` 등)만. 코드·설정 파일에 비밀번호 금지.
