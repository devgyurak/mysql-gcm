---
paths:
  - "docs/**"
  - "spec/**"
  - "README.md"
  - "README-KO.md"
---
# 문서 · 스펙 규칙

- `docs/design.md` 가 근거의 원본. 코드와 다르면 코드가 틀린 것이거나 문서를 먼저 개정해야 한다. §8 "확인됨/미확인" 표는 사실이 확인될 때마다 갱신한다 (근거 링크 포함).
- README 첫 화면 순서: 한 줄 요약 → **운영 제약 (design §6 전부)** → 지원 매트릭스 → 설치 → 함수 표. 제약을 아래로 내리지 않는다.
- `spec/envelope.md` 는 구현 언어 중립. 바이트 오프셋 표 + 실패 의미론 표 + 예시 hex. 구현자가 이 문서만 보고 만들 수 있어야 한다.
- `spec/test-vectors.json` 스키마: `{ "version": 1, "vectors": [ { "id", "kind": "random|det|nist", "key_hex", "nonce_key_hex"?, "nonce_hex"?, "aad_hex", "plaintext_hex", "envelope_hex", "expect": "ok|bad_tag|bad_envelope" } ] }`. 필드 추가는 minor, 의미 변경은 major.
- 문서 언어: README·spec·docs 는 영어 (오픈소스). `README-KO.md` 는 사용자가 요청한 한국어 번역이며 README 의 운영 제약·지원 버전·명령·예제가 바뀌면 같은 변경에서 함께 갱신한다. 두 README 상단의 언어 링크를 유지한다. `docs/design.md` 는 원본이 한국어이므로 유지하되 영어 요약 `docs/design.en.md` 를 Phase 1 에 추가.
- 라이선스는 **GPLv2 로 확정**됐다 (2026-09-28, design §7). `LICENSE` 에 전문, 소스에 `SPDX-License-Identifier: GPL-2.0-only`, README 두 판에 `LICENSE` 링크. "pending legal review" 표기는 더 쓰지 않는다. 다른 라이선스로 바꾸려면 design §7 을 먼저 개정한다.
