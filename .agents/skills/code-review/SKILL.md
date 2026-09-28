---
name: code-review
description: 이 저장소의 PR/diff 를 P1·P2·P3 우선순위와 리뷰어 체크리스트 순서로 리뷰하고 결과를 정해진 형식으로 보고하는 절차. "리뷰해줘", PR 검토, 셀프 리뷰 요청에 사용.
---

# code-review

규칙 원본 `.agents/rules/code-review.md`. 체크리스트 순서를 바꾸지 않는다: 정확성 → 안전 → 서버 안정성 → 아키텍처 → 테스트 → 호환성 → 문서 → 스타일.

## 절차
1. 범위 확정: `git diff --stat <base>...HEAD`. 순 변경 400줄 초과면 첫 코멘트로 분할 요청(P2) 하고 계속 리뷰.
2. 변경 파일이 암호 경로(`src/gcm.cc` `envelope.cc` `nonce.cc` `sysvar.cc` `spec/**` `scripts/gen-vectors.py`)에 닿으면 **이 스킬을 실행하는 부모 에이전트가** `code-reviewer` 와 `crypto-reviewer` 를 각각 띄우고 두 보고를 합친다. 이 저장소의 리뷰어는 추가 위임을 하지 않도록 구성하므로 `code-reviewer` 안에서 이 단계를 기대하지 않는다 (`NEEDS: crypto-reviewer` 표시가 오면 부모가 실행).
3. 자동 검사 — `rg` 사용, 언어별 범위 분리. 종료 코드 해석: **0 = 일치 있음(P1 후보) / 1 = 없음(통과) / 2 = 검색 실패(보고에 "검사 실패" 로 명시, 통과 아님)**.
   ```
   python3 scripts/check-architecture.py
   # C++ (src/, tests/unit/): 레거시 OpenSSL 심볼, 비암호 난수, 키를 담는 std::string, 로그 우회
   rg -n --type cpp -e 'EVP_aes_' -e '\bHMAC\(' -e '\b(s?rand)\(' -e 'std::string\s+\w*key' -e 'printf[^;]*key' -e 'general_log|log_raw' src tests/unit
   # Python (scripts/, tests/): 허용 라이브러리 외 프리미티브 (cryptography 의 hmac.HMAC 는 허용)
   rg -n --type py -e '^\s*(from|import)\s+(Crypto|Cryptodome|nacl|hashlib)\b' -e 'random\.(random|randint|getrandbits)' scripts tests
   ```
   `check-architecture.py` 는 0=통과, 비영=실패다. 위의 0/1/2 해석은 `rg` 에만 적용한다.
   검색 일치 항목은 파일:라인을 보고 규칙 위반인지 판단한 뒤 P1 로 올린다 (예: 주석·문서 문자열 속 일치는 제외).
4. 체크리스트 항목별로 diff 를 읽고 **재현 조건이 있는** 결함만 기록. 추측은 `Q`.
5. 테스트: 변경된 함수마다 대응 테스트가 있는지, GWT 형식인지, `.result`/`.expected` 변경이 설명됐는지.
6. 가능하면 실제로 실행: `ctest --test-dir build/unit`, `scripts/verify.sh 8.4`. 실행 결과를 보고에 적는다 (실행 못 했으면 "미실행"으로).

## 보고 형식
```
## Review: <PR 제목 또는 브랜치>
Ran: unit ✅ / verify.sh 8.4 ✅ / crypto-reviewer ✅ (또는 미실행 사유)

P1 (N)
- src/envelope.cc:42 — tag offset uses ct_len instead of env_len-16; 재현: 1-byte plaintext det envelope → reads 1 byte past buffer. 제안: `env.size() - kTagLen`.
P2 (N)
- tests/unit/gcm_test.cc — 새 함수 `open_v1` 에 테스트 없음 (testing.md §단위).
P3 (N)
- ...
Q (N)
- ...
Verdict: BLOCK (P1 존재) | APPROVE-WITH-P2 | APPROVE
```
파일:라인, 무엇이 왜, 재현, 제안 — 네 요소가 없는 코멘트는 내지 않는다.
