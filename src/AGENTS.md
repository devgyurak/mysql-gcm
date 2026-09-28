# src/ — component 소스

루트 `AGENTS.md` 에 더해 아래 규칙이 이 디렉터리에 적용된다. 작업 전 읽는다.
- `.agents/rules/architecture.md` — 모듈 책임, 의존 방향, 상태 수명, 서버 호환성, 테스트 경계
- `.agents/rules/component-src.md` — component 서비스, charset 태깅, 등록·해제 API
- `.agents/rules/crypto-safety.md` — EVP 이름 fetch, 키 32B, cleanse, strict 의미론
- `.agents/rules/stack-cpp.md` — C++17, RAII, 오류 enum, clang-tidy

스킬: `.agents/skills/mysql-component`, `gcm-crypto`, `sysvar-config`. API 가 불확실하면 `component-api-researcher` 역할 프롬프트(`.claude/agents/`)로 헤더를 확인한다.
