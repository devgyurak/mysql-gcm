@AGENTS.md

# Claude Code 전용 보충

- 규칙 원본: `.agents/rules/*.md`. Claude 는 `scripts/agents-sync.sh` 가 생성한 `.claude/rules/*.md` 를 읽는다 (프론트매터 `paths:`·본문 보존). 생성물을 직접 수정하지 않는다.
- 스킬 원본: `.agents/skills/` (`.claude/skills/` 는 심링크). 서브에이전트 원본: `.claude/agents/`. 원본을 고친 뒤 `scripts/agents-sync.sh` 로 도구별 어댑터를 재생성한다.
- 권한·훅은 `.claude/settings.json`. 훅 `.claude/hooks/guard.sh` 가 force-push 와 키 파일 스테이징을 차단한다. 우회하지 말고 사용자에게 알린다.
- 병렬화 가능한 조사(서버 헤더 확인, 벡터 검증, 빌드 로그 분석)는 서브에이전트에 위임하고 결론만 받는다.
- 큰 변경은 EnterPlanMode 로 계획을 먼저 보인다: 봉투 포맷, sysvar 이름, 함수 시그니처, CI 매트릭스 변경이 여기에 해당한다.
- 빌드·테스트 결과는 있는 그대로 보고한다. 실패한 테스트를 "환경 문제"로 넘기지 않는다.
