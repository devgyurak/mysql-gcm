# MySQL GCM 암복호화 함수 (component) — 설계와 절차

> **언어.** [English](design.md) · 한국어
>
> 이 문서는 [`design.md`](design.md) 의 한국어 번역입니다. **영어판이 정본**이고, 두 문서가 다르면
> 영어판이 맞습니다 (`.agents/rules/docs.md`). 설계를 바꿀 때는 두 문서를 같은 PR 에서 함께 고칩니다.

> ## 개정 A11 (2026-10-07) — 복호화 컨텍스트와 결정적 nonce 키의 문장 단위 재사용
>
> **상태: 제안 — 이 PR 뒤에 구현돼 있고, 머지되면 효력을 가진다.** 아래 수치는 개발자 장비의
> 프로토타입 측정값(다른 컨테이너가 돌고 있는 arm64 노트북)이며, 절감의 크기가 아니라 모양을
> 보이려고 인용한다. CI 측정값이 `docs/perf.md` 에 뒤따르며 이 수치를 대체한다.
>
> §8 은 한 항목을 일부러 미해결로 남겨 두었다: `derive_nonce_key` 는 키에만 의존하는데
> `encrypt_det` 가 행마다 다시 계산하고, 이를 `UDF_INIT` 당 캐시하려면 **키 복사본을 행 사이에
> 보관**해야 하는데, `crypto-safety.md` 는 개정과 보안 검토 없이는 이를 허용하지 않는다. 이 문서가
> 그 개정이며, 같은 키를 행마다 새로 스케줄하는 나머지 한 곳 — `gcm_decrypt` 뒤의 EVP 컨텍스트 —
> 까지 넓힌다.
>
> **결정.** `UDF_INIT` — 한 UDF 항목의 `init` 부터 `deinit` 까지의 수명으로, **한 문장의 한 번의
> 실행**이고 항상 한 스레드가 구동한다 — 는 인스턴스별 상태에 다음을 보관할 수 있다:
>
> (추정이 아니라 8.0.43, 8.4.11, 9.4.0 소스에서 확인한 것이다. `func_init` 은 `udf_handler::fix_fields`
> 에서, `func_deinit` 은 그 실행이 끝날 때 `Item_udf_func::cleanup()` 에서 불린다. UDF 를 참조하는
> prepared statement 는 `EXECUTE` 마다 다시 prepare 되므로(`Prepared_statement::execute_loop`,
> `has_udf()`) 이 쌍은 두 실행에 걸치지 않는다. 스칼라 UDF 의 handler 는 복사 생성되지 않는다 — 그
> 경로는 이 component 가 등록하지 않는 집계 UDF 전용이다 — 그리고 `Item` 은 한 `THD` 의 한 문장
> arena 에 속한다.)
>
> - (a) `gcm_decrypt`: 키 스케줄이 설정된 `EVP_CIPHER_CTX` 하나와, 그 스케줄에 쓰인 키 바이트의
>   복사본(최대 32바이트), 그리고 그것이 속한 수트;
> - (b) `gcm_encrypt_det`: 키 바이트의 복사본(최대 32바이트)과 유도된 32바이트
>   `nonce_key = HMAC-SHA256(key, label)`.
>
> `gcm_encrypt`(랜덤 nonce)에는 캐시를 두지 않는다. 그 EVP 컨텍스트 재사용은 나중에 측정해 볼 수
> 있는 후보이고, 여기서 결정하지 않는다.
>
> **불변 조건.** 구현이 전부 강제하고 단위 테스트가 고정한다:
>
> - 보관한 키 복사본은 들어온 키와 `CRYPTO_memcmp`(상수 시간)로 비교한다. 길이와 수트는 공개
>   정보이므로 비교를 조기 종료해도 되지만, 바이트는 안 된다.
> - 복사본은 바이트나 수트가 다를 때만 교체하고, 교체 전에 이전 복사본을 `OPENSSL_cleanse` 한다.
> - 암호 연산의 **모든** 실패에서 — 어느 단계의 OpenSSL 오류든, 그리고 `bad_tag` — 복사본을 소거하고
>   컨텍스트를 잊는다. 다음 행은 처음부터 시작하며, 방금 오류를 보고한 컨텍스트를 절대 신뢰하지 않는다.
>   컨텍스트를 건드리기 *전에* 돌아가는 사전 검사 — 어느 수트에도 없는 키 길이, 잘못된 봉투 — 는
>   컨텍스트를 그대로 둔다. 한 행의 잘못된 키 길이는 그 행의 SQL 오류이지, 유효한 키 스케줄을 버릴
>   이유가 아니다. nonce 키 캐시도 같은 규칙을 따른다: HMAC 실패에서는 잊고, `bad_key_len` 사전
>   검사에서는 건드리지 않는다.
> - `deinit` 은 둘 다 소거한다.
> - 키를 잊을 때 컨텍스트도 함께 reset 한다. `EVP_CIPHER_CTX` 안의 키 스케줄은 키와 동등한 자료이므로,
>   그것을 만든 복사본보다 오래 남지 않는다.
> - 상태는 스레드 사이에서 공유하지 않으며, `UDF_INIT` 하나는 스레드 하나가 구동한다.
> - 기록하거나 받아들이는 바이트는 아무것도 바뀌지 않는다. `spec/envelope.md` 의 바이트 배치는 그대로이고,
>   `nonce_key` 를 "호출마다" 유도한다고 적은 문장 하나만 "한 `UDF_INIT` 안에서 키가 바뀔 때"로 바로잡는다.
>   §7 이 버전 올림 없이 허용하는 수정이다. 기존 벡터 테스트를 재사용 경로로 돌려 출력이 바이트 단위로
>   동일함을 증명한다.
> - 컨텍스트를 다시 만드는 행은 재사용하는 행보다 오래 걸린다. 그 차이가 무엇을 누구에게 드러낼 수
>   있는지는 키가 어디서 오는지에 달려 있다 — 아래 위협 모델을 보라.
>
> **이유.** 시간은 암호 자체가 아니라 행마다 하는 준비에 있다:
>
> - 코어: 16바이트 `open` 이 353 → 170 ns. 그 크기에서는 호출마다 하는 `EVP_CIPHER_CTX_new`,
>   `Init` 두 번(둘째가 키 스케줄), free 가 비용의 전부다.
> - SQL: MySQL 9.4 에서 100,000행에 대한 `gcm_decrypt(col) LIKE`. p95 가 세션 1에서
>   49.6 → 23.2 ms, 세션 8에서 126.4 → 27.2 ms; `AES_DECRYPT` 대비 비율은 1.06 → 0.48, 1.27 → 0.26.
>   세션 8의 이득(행당 약 1 µs)은 직렬 벤치가 예측하는 값(행당 약 180 ns)보다 훨씬 크다. 한 가지
>   가설은 OpenSSL 3 의 호출별 컨텍스트 준비에서 스레드 간 경합이 생긴다는 것이지만, 이 측정은 원인을
>   분리하지 않았으며, 이 개정이 기대는 것은 설명이 아니라 관측된 이득이다.
> - 결정적 변형: 행당 HMAC 한 번이 사라진다. MySQL 8.0 에서 `BENCHMARK()` 로 서버 쪽에서 잰
>   호출당 약 0.75 µs (2.29 → 1.52 µs). 함수 항목 하나가 여러 행에 걸쳐 평가되는 문장 —
>   `INSERT … SELECT`, `UPDATE`, 조인 — 에서만 효과가 있다. 다중 행 `INSERT … VALUES` 는 식마다
>   자기 `UDF_INIT` 을 가지므로 얻는 것이 없다.
> - 부하 러너에 추가한, 같은 행을 세도록 술어를 맞춘 대조 질의 두 개는 스캔과 `gcm_decrypt` 를 함께
>   부르는 스캔 사이의 p95 차이를 노트북에서 `gcm_decrypt(col) LIKE` 질의 p95 의 73~85% 로 보였다
>   (행당 384~391 ns, bare open 약 280 ns 와 나란히). 이는 질의 간 차이이지 구성 요소 시간이 아니며,
>   복호화 호출이 질의의 대부분이라는 것을 말할 뿐 호출 안의 어디에 시간이 드는지는 말하지 않는다.
>
> **노출, 솔직하게.** 바뀌는 것은 키 재료의 *보유 기간*이다. A11 이전에는 키 사본과 유도된 재료가
> 연산 하나, 행 하나 동안만 살았다. 이후에는 UDF 항목이 **마지막으로 쓴 키** — 그 사본, 컨텍스트 안의
> 키 스케줄, 결정적 변형이라면 `nonce_key` — 가 다른 키나 수트로 암호 연산에 도달한 행이 오거나, 암호
> 연산이 실패하거나, 실행이 끝나 항목의 `deinit` 이 불릴 때까지 산다. 암호 연산에 도달하지 않는 행은
> 그것을 바꾸지 않는다: NULL 인자, 너무 긴 인자, 잘못된 봉투, 어느 수트에도 없는 키 길이, 그리고 세션을
> 쓰지 않는 레거시 `0x01` 봉투는 모두 이전 키를 그대로 둔다. 한도는 같다 — 실행보다 오래 남는 것은
> 없다 — 다만 그것을 끝내는 것이 항상 "다음 행"은 아니다. 그것이 얼마나 더하는지는 키가 어디서 오느냐에 달려
> 있고, 두 경우는 같지 않다:
>
> - **호출자가 문장에 상수로 주는 키** — 리터럴, 사용자 변수, 바인딩된 파라미터. README 가 문서화한
>   사용법이다. 서버는 그 키를 실행 내내 인자 버퍼와, §6 이 general/slow 로그에 닿는다고 적어 둔 문장
>   텍스트에 이미 들고 있고, 호출자는 이미 그 키를 안다. A11 은 같은 기간 동안 메모리상 위치를 하나
>   더할 뿐이며, 문장 중간의 코어 덤프에는 어느 쪽이든 키가 들어 있다.
> - **행마다 계산되는 키** — 컬럼에서 읽거나, 식으로 유도하거나, definer 권한으로 도는 view 나 저장
>   루틴이 넘기는 키로, 호출자가 알아서는 안 될 수 있다. 이 경우 서버는 각 행의 키를 그 행을 평가하는
>   동안만 들고 있고, A11 은 가장 최근 키를 그 행을 넘어 실행이 끝날 때까지 보관한다. 즉 UDF 항목당
>   실행당 최대 키 하나의 보유가 늘어나며, 이 개정은 그것을 받아들인다 — 문장으로 한정되고, 모든 출구에서
>   소거되며, 공유되지 않는다 — 그리고 숨기지 않고 이름 붙인다.
>
> **타이밍.** 직전 행과 같은 키를 쓰는 행은 컨텍스트를 다시 만드는 행보다 빠르다(측정한 하드웨어의 코어
> 기준 약 120 ns 대 약 300 ns). 위 첫 번째 경우에는 호출자가 모든 키를 골랐으므로 그 차이는 아무것도
> 알려 주지 않는다. 두 번째 경우에는 원리상, 행 평가 시간을 잴 수 있는 사람에게 *연속한 행이 같은 키를
> 썼는지* 를 — 키 바이트는 결코 아니다 — 알려 주는 신호가 된다. 클라이언트가 보는 것은 문장 전체의
> 소요 시간만이 아니다. 스트리밍 결과(`mysql_use_result` 나 서버 측 커서)는 행이 만들어지는 대로
> 전달되므로 각 행의 도착 시점을 관찰할 수 있고, 원리상 행 단위 차이도 관찰할 수 있다. 그 정밀도는
> 실행 계획, 서버와 네트워크의 버퍼링, 드라이버에 따라 달라지며, 적은 행만 돌려주는 필터나 정렬·집계는
> 대부분을 가린다. hit 와 miss 시간을 구별하는 공격은 입증된 바 없고 주장하지도 않는다. 따라서 A11 이
> 받아들이는 위협 모델은 이렇다: **이미 문장을 제출하고 결과가 도착하는 대로 관찰할 수 있는 공격자는
> 평가된 연속 행이 같은 키를 썼는지 알 수 있을지 모르나, 어떤 키인지는 알 수 없다.** 여기에는 공격자가
> 나란히 놓기로 고른 행도 포함된다. 행마다 키가 다른 view 위에서 `WHERE` 와 `ORDER BY` 로 호출자는 어떤
> 두 행이 연속해서 평가될지 정할 수 있고, select 목록의 `SYSDATE(6)` 같은 행 단위 시계나 행 도착 시점은
> 반복 질의로 평균 낼 수 있는 행 단위 소요 시간을 준다. 따라서 신호는 "키가 얼마나 자주 바뀌는가"만이
> 아니라 원리상 **공격자가 고른 두 행이 같은 키를 쓰는가** 이다. 이것은 측정할 수 있을지에 대한
> 가설이지 측정된 결과가 아니다. 그것조차 문제가 되는 배포 — 그룹 구성을 알아서는 안 되는 호출자를 위해 행마다
> 키를 고르는 definer 권한 루틴 — 는 이 개정의 수용에 기대지 말고 그런 키를 행 단위 식 밖에 두어야
> 한다. 이 개정이 함께 이름 붙이는 위험:
>
> - 복사본은 연산이 진행 중일 때만이 아니라, 함수가 평가되는 행과 행 사이의 유휴 시간을 포함해 실행
>   전체 동안 살아 있다.
> - 서버 크래시는 `deinit` 을 건너뛰므로 복사본은 소거되지 않는다. 서버 자신의 인자 버퍼도
>   마찬가지다.
> - 상태를 스레드 사이에서 재사용하는 버그는 정확성 버그이자 동시에 비밀성 버그다. 이 개정이 기대는
>   가정은 단일 스레드 `UDF_INIT` 모델이고, 이 PR 의 어댑터 테스트가 `init` 당 상태 하나가 만들어짐을
>   고정한다.
>
> 선례: `UDF_INIT` 상태는 이미 `gcm.strict` 와 `gcm.min_key_bytes` 스냅샷을 정확히 이 수명 동안
> 들고 있다 (A5, A10). 새로운 점은 보유하는 상태가 비밀이라는 것이다.
>
> **기각한 것.** `UDF_INIT` 보다 오래 사는 캐시나 전역 캐시 — 수명이 무한하고 행 경로에 잠금이
> 필요해진다. 그리고 전체 키 바이트 외의 것으로 색인하는 캐시 — 키의 해시도, 길이도, 인자 버퍼의
> 주소도 안 된다.
>
> **영향:**
>
> | 영역 | 변경 |
> |---|---|
> | `.agents/rules/architecture.md` §3, §5 | `UDF_INIT` 행에 보유 상태 둘이 추가된다; 연산 행은 EVP *연산*과 일시적 비밀을 유지한다; 행 간 재사용은 이 개정이 허용한 것으로 한정된다 |
> | `.agents/rules/crypto-safety.md` | 키 복사 규칙에 이 하나의 예외와 그 불변 조건이 들어간다; `UDF_INIT` 보다 오래 사는 복사본, 전체 키 바이트 외의 것으로 색인하는 캐시는 차단 패턴이다 |
> | `src/gcm.{h,cc}`, `src/nonce.{h,cc}`, `src/udf_*.cc` | `UDF_INIT` 상태에 매달린 재사용 복호화 경로와 nonce 키 캐시 경로 |
> | `tests/unit`, `tests/adapter` | 위 불변 조건; 재사용 경로를 통과하는 벡터; `init` 당 상태 하나 |
> | `docs/perf.md` | 여기 인용한 프로토타입 수치를 대체하는 CI 측정값 |

> ## 개정 A10 (2026-10-06) — AES-128-GCM 과 AES-192-GCM
>
> **상태: 전부 구현됨.** 세 수트가 모두 출시됐다 — `0x02`/`0x03`(AES-256), `0x06`/`0x07`(AES-192),
> `0x04`/`0x05`(AES-128). `gcm.min_key_bytes` 기본값이 32 이므로 AES-256 아래는 전부 옵트인이다.
> `spec/envelope.md` 는 v3 다. NIST CAVP KAT 를 모든 수트에 대해 넣었다 — 2,250개, 수트당 750개,
> 그중 인증 실패가 각각 191 / 190 / 196 개다.
>
> AES-192 추가는 이 개정이 스스로 주장한 "수트 하나는 표 한 줄 + `EVP_CIPHER_fetch` 하나" 를 시험했다.
> 성립했다 — 파일 4개, 17줄. 나머지는 전부 표에서 유도된다: 파싱, version 과 키 길이의 일치 검사, nonce
> 유도, 에러 메시지, 바닥. 공짜가 **아니었던** 것은 테스트와 문서 표면이다. 열 몇 군데가 AES-192 를
> 미구현이라고 단언하고 있었고, 하나씩 의도적으로 뒤집어야 했다.
>
> **여기서 확정한 것과 그 근거** (`0x05` 를 출시한다는 것은 이들을 확정한다는 뜻이므로):
>
> - **AES-128 에도 `gcm_encrypt_det` 를 제공한다.** 결정적 nonce 는 수트와 무관하게 HMAC-SHA256 을
>   96비트로 자른 것이므로 §5.2 의 충돌 경계가 키 길이로 움직이지 않고, 구성이 노출하는 것(동등성·빈도·
>   길이)도 AES-256 이 이미 갖는 것과 같다. 128비트 키가 바꾸는 것은 암호 자체의 여유이고, 그건 운영자가
>   키 길이를 고름으로써 내리는 키 강도 결정이지 변형을 빼는 방식으로 component 가 대신 내릴 결정이
>   아니다. 빼는 것은 일관성도 없다 — 128비트 `gcm_encrypt` 는 여전히 쓸 수 있으므로, 결정성이 필요한
>   배포는 해시 컬럼 같은 *더 나쁜* 답으로 밀려난다.
> - **세 수트가 유도 레이블 하나를 공유하며, 이는 바꾸지 않고 받아들인다.** 초안은 "수트별 레이블이
>   `0x03` 과 `0x05` 를 비교 불가능하게 만든다"고 적었는데 그건 틀렸고 철회한다. 둘은 이미 version
>   바이트부터 달라 같게 비교되지 않으며(`tests/adapter` 와 MTR 케이스가 모두 단언한다), **새** `0x05`
>   에만 별도 레이블을 줘도 기존 `0x03` 봉투의 재현성은 그대로다.
>
>   실제 이유는 더 좁다. 레이블은 암호 키와 HMAC 키를 분리하기 위해 존재하고 그 역할은 모든 수트에서
>   수행되며, `crypto-safety.md` 는 그것이 **한 곳의 상수 하나**여야 한다고 요구한다. 레이블이 둘이면
>   바로 그 파일에 수트별 매핑이 생기는데, 그 대가로 사는 분리는 아직 필요가 입증되지 않았다 — 수트는
>   이미 서로 다른 키로 분리돼 있고, 유일하게 문서화된 예외가 짧은 키와 그 제로 확장이 같은 nonce 키를
>   유도한다는 것(RFC 2104 §2)이다. 그 예외 자체는 공격이 아니며(두 AES 키가 다르고 GCM 의 치명적 경우는
>   한 키 아래의 한 nonce 다), `spec/envelope.md` §2.5 에 "구현이 의존해서는 안 되는 것"으로 적혀 있다.
>
>   보안 검토가 필요하다고 판단하면, 수트별 레이블은 **기존 `0x03` 데이터에 비용이 들지 않는다** — 주장의
>   범위는 거기까지이고, `0x05` 가 출시되는 순간 그 범위가 좁아진다. 그 뒤로는 레이블 변경이 `0x03` 에서와
>   똑같이 `0x05` 데이터의 결정적 재현성을 깨뜨린다: 같은 평문이 저장된 봉투를 재현하지 못하게 되므로 그
>   컬럼의 조인·UNIQUE·정확일치가 맞지 않게 된다. 자체 version 바이트와 이관이 필요하며, 이는
>   `spec/envelope.md` §7 의 일반 규칙이지 예외가 아니다. 이 변경이 싼 구간은 `0x05` 가 아직 누구의
>   데이터에도 없을 때, 즉 지금이다.
>
> **보안 검토에 남기는 것:** 공유 레이블을 장래 스펙 버전에서 수트별로 바꿀 것인지, 그리고
> `gcm.min_key_bytes` 계약 4항 — 그중 셋은 구현이 답했고(암호화 전용, GLOBAL 전용, 32 로 fail closed),
> 넷째인 위반 에러는 `bad_key_len` 과 구분되는 메시지다. 검토는 이 선택들을 확인하는 것이지 발견하는
> 것이 아니다.
>
> §2 와 개정 A1 은 수트를 AES-256-GCM 으로 고정한다. 봉인에 쓰는 cipher 는
> `EVP_CIPHER_fetch("AES-256-GCM")` 하나뿐이고, 키는 정확히 32 바이트를 호출마다 검사한다.
> 이 개정은 **AES-128-GCM 과 AES-192-GCM 을 나란히 추가한다**. AES-256-GCM 은 그대로 기본값이자
> 권장값이고, 작은 키 길이는 상호운용성과 규정 준수를 위한 것이지 속도를 위한 것이 아니다.
>
> **성능 이득은 아직 측정하지 않았다.** AES-128 은 AES-256 보다 라운드 수가 적으므로 암호 연산 자체는
> 싸지만, 그것이 SQL 수준에서 얼마나 남는지에 대한 수치가 이 프로젝트에는 없고 인용해서도 안 된다.
> `docs/perf.md` 의 부하 결과는 GCM 과 CBC 빌트인의 비교이지 AES-128 과 AES-256 의 비교가 아니다.
> 그리고 두 암호 사이의 0.9 근처 비율만으로는 쿼리에서 암호가 차지하는 몫을 알 수 없다 — 비용이 비슷한
> 두 암호는 그 비용이 크든 작든 같은 비율을 내므로, 행 스캔이 지배하는지 여부를 이 수치들은 말해주지 않는다.
>
> 측정은 둘로 나뉘고 어느 쪽도 상대의 질문에 답하지 않는다. **`tests/bench` 는 수트 사이의 코어 차이를
> 측정한다** — 서버 없이 돌므로 SQL 에 대해서는 아무 말도 할 수 없다. **종단 SQL 차이는 부하 시나리오가
> 측정한다.** 작은 수트에 대한 성능 주장은 둘 다 있고 난 뒤에 한다.
>
> **수트는 키 길이로만 선택한다.** 16 바이트 → AES-128-GCM, 24 → AES-192, 32 → AES-256. 새 함수 인자도,
> 새 sysvar 도, 호출 형태의 변경도 없다.
>
> 이것이 핵심 결정이고, 그 트레이드오프는 정확하게 적어야 한다.
>
> 명시적 선택자(`gcm_encrypt(plaintext, key, suite)`)가 개정 A8 이 AAD 에 대해 부과하는 종류의 호출 간
> 일관성 의무를 **만들지는 않는다**. AES 수트별 키 길이는 [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final)
> 로 고정돼 있으므로, component 가 어긋나는 (수트, 키 길이) 조합을 즉시 거부하면 된다 — AES-128 에
> 32바이트 키는 바로 에러이고, 접기도 자르기도 하지 않는다. 수트마다 유효한 키 길이가 정확히 하나이므로
> 한 키를 두 강도로 쓸 수 없고, 운영자에게 새 규칙이 생기지도 않는다.
>
> 길이 추론이 실제로 얻는 것은 **API 단순성**이다. 호출 형태가 바뀌지 않고, 애플리케이션이 틀릴 네 번째
> 인자가 없다. 포기하는 것은 **교차 검증**이다 — 호출자가 의도한 수트와 실제로 전달된 키를 맞춰볼 기회.
> "AES-256 을 의도했는데 키가 16바이트로 잘렸다"는 의도와 키의 불일치이고, 선택자는 그것을 에러로 만든다.
> 길이 추론에는 비교할 의도가 없다. 이는 아래 "대가" 절의 같은 문제를 반대편에서 본 것이고, 두 절은 함께
> 읽어야 한다.
>
> 그럼에도 여기서는 길이 추론을 택한다. 단, 절단 방지를 **버리지 않고 유지한다**는 조건에서다 —
> 기본값 32 의 `gcm.min_key_bytes` 가 기본값을 그대로 둔 배포에 대해 그 방지를 유지한다. 이것이 선택자와
> **동등하지는 않다**. 최소 길이 정책은 서버 전역의 하한선이지 호출마다 호출자의 의도를 검증하는 것이
> 아니고, 한 애플리케이션 때문에 하한선을 낮춰야 하는 혼합 배포에서는 모두가 그 방지를 잃는다 — 아래 계약
> 항목 참조. 완화책을 아예 채택하지 않는다면, 둘 다 없이 출시할 것이 아니라 이 결정을 선택자 쪽으로
> 재검토해야 한다.
>
> **봉투: 새 version 바이트 네 개.** `spec/envelope.md` §7 이 기존 바이트를 동결한다 — 새 형식은 새
> version 바이트이지 기존 것의 재정의가 아니다. 따라서 `0x02`·`0x03` 은 정확히 AES-256-GCM 을 계속 뜻한다.
>
> ```
> 0x02  AES-256-GCM 무작위      (변경 없음)
> 0x03  AES-256-GCM 결정적      (변경 없음)
> 0x04  AES-128-GCM 무작위
> 0x05  AES-128-GCM 결정적
> 0x06  AES-192-GCM 무작위
> 0x07  AES-192-GCM 결정적
> ```
>
> 각각의 배치는 `0x02`·`0x03` 과 동일하다 — `version(1) || nonce(12) || ciphertext || tag(16)`, 즉
> 평문 + 29 바이트. version 바이트와 키 길이만 다르다. `0x02`·`0x03` 에서 시작된 짝수=무작위·홀수=결정적
> 패턴이 이어지지만, 이것은 가독성 속성이지 구현이 의존해도 되는 규칙이 아니다. 대응은 산술이 아니라 표다.
>
> 수트를 봉투에 기록하는 것이 꼭 필요하지는 않다 — 복호화 시 호출자가 주는 키가 이미 수트를 결정한다 —
> 그러나 봉투를 **자기 서술적으로** 유지한다. 개정 A2 가 결정적 nonce 를 재계산하지 않고 저장하기로 한 것과
> 같은 선택이다. 이관·감사·키 교체 도구가 키를 쥐지 않고도 그 행을 무엇이 만들었는지 알 수 있다.
>
> **version 바이트가 기대 키 길이를 정하고, 불일치는 `bad_key_len` 이다.** `0x02` 봉투를 16 바이트 키로
> 복호화하면 태그 실패가 아니라 불일치를 지목하는 에러가 난다. 이것이 얻는 것은 정확히 한 가지 구분이다 —
> **봉투가 요구하는 키 길이와 전달된 키 길이가 어긋난다**는 것을 태그 실패와 구분한다. 이 구분이 없으면
> 같은 상황이 `bad_tag` 로 보고되어 운영자를 데이터 손상 쪽으로 이끈다. 절단 탐지기가 아니다 — 잘린 키가
> 드러나지 않는 경우는 아래 "대가" 절에 있고, version 바이트가 손상돼도 같은 에러가 난다.
>
> **바뀌지 않는 것:**
>
> - 결정적 nonce 유도와 그 레이블. `nonce_key = HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")` 는 모든 키
>   길이에 대해 바이트 그대로 유지되고, 레이블은 `spec/envelope.md` §7 이 동결했다.
>
>   레이블을 바꿔도 기존 데이터의 **복호화는 깨지지 않는다**. 개정 A2 가 봉투에 nonce 를 저장한 이유가
>   바로 복호화가 nonce 를 재계산하지 않게 하려는 것이다. 깨지는 것은 같은 입력을 다시 암호화했을 때
>   기존 암호문이 재현되지 않는다는 것이고, 그것이 결정적 변형의 존재 이유 전부이므로 걸린 것은
>   JOIN·UNIQUE·정확일치의 연속성이다. 레이블은 유지한다 — 이유는 복호화 가능성이 아니라 연속성이다.
>
>   HMAC-SHA256 은 임의 길이 키를 받으므로 새 유도식이 기계적으로 필요하지는 않다. 그렇다고 **키 길이가
>   다르면 도메인이 분리된다는 결론이 따라 나오지는 않는다.**
>   [RFC 2104 §2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2) 는 블록(64바이트)보다 짧은 키를
>   0 으로 패딩하므로, 16바이트 키 `K` 와 32바이트 키 `K ‖ 0¹⁶` 는 **동일한** nonce 키를 유도하고 따라서
>   같은 평문에 같은 nonce 를 만든다. 가정이 아니라 실제로 확인했다. 이 쌍 자체가 GCM nonce 재사용은
>   아니다 — 두 AES 키가 다르고, GCM 의 치명적 경우는 한 키 아래의 한 nonce 다 — 그러나 "길이가 다르면
>   도메인이 분리된다" 는 근거로 쓸 수 없고, 새 수트에 명시적 도메인 분리가 필요한지는 이 개정이 아니라
>   아래 보안 검토가 답할 문제다.
> - 태그 길이 16, nonce 길이 12 — 세 수트 모두.
> - strict 의미론, 실패 코드, AAD 규칙.
> - legacy `0x01` CBC 경로. AES-256-CBC 복호화 전용으로 유지된다 (아래 미해결 항목 참조).
> - 결정적 JOIN·UNIQUE 동작. 암호문은 같은 키에서만 비교 가능하고 키는 길이가 하나뿐이므로, 기존의
>   "같은 키·같은 AAD" 요건이 이미 이를 포함한다. 이 개정으로 새로 생기는 운영 규칙은 없다.
>
> **대가를 그대로 적는다.** 지금은 `key.size != 32` 가 에러이므로, 전송 중에 잘린 키 — 클라이언트 버그,
> 잘못된 환경변수, 잘못 자른 버퍼 — 가 요란하게 실패한다. 이 개정 이후에는 32 바이트 키가 16 바이트로
> 잘린 것이 **유효한 AES-128 키**이고, `gcm_encrypt` 가 그것으로 봉인하고 성공을 보고한다. 의도보다 낮은
> 강도로 암호화되는데 아무도 그렇다고 말해주지 않는다.
>
> **나중에 반드시 발견되는 것도 아니다.** 복호화가 이를 드러내는 것은 누군가 *의도했던* 키로 읽을 때뿐이다.
> 쓰기와 읽기가 모두 같은 16바이트 잘린 키를 쓰면 `0x04` 봉투와 일치하므로 둘 다 무한히 성공한다.
> 불일치는 원래 32바이트 키로 그 행을 처음 읽는 순간에 드러나고, 그 순간은 백업 복구일 수도, 이관일 수도,
> 영영 오지 않을 수도 있다.
>
> 위의 `bad_key_len` 구분은 여전히 둘 가치가 있지만, 그것이 말해주는 바를 정확히 읽어야 한다 — 봉투와
> 전달된 키가 길이에 대해 어긋난다는 진단이다. 키가 잘렸다는 증거는 아니다. version 바이트 손상도 같은
> 신호를 낸다.
>
> 이것이 이 기능의 실제 가격이고, 키 길이가 선택자인 한 설계로 없앨 수 없다. 완화책이 둘 있고 그 선택은
> **여기서 확정하지 않는다**:
>
> 1. sysvar — `gcm.min_key_bytes` (기본 32, 24 나 16 으로 설정 가능) — 작은 수트를 쓸 의도가 없는 배포가
>    서버에서 거부하게 한다. 현재 동작이 기본값으로 유지된다: 아무것도 하지 않은 설치는 변화가 없고,
>    잘린 키는 여전히 요란하게 실패한다. 비용은 sysvar 하나와 개정 A5 의 8.0·8.4 GLOBAL 전용 스코프 문제다.
>
>    채택한다면 그 계약을 먼저 확정해야 하고, 아래는 구현 세부가 아니다:
>
>    - **새 암호화에 적용하고 기존 데이터의 복호화에는 적용하지 않는다.** 그러지 않으면 정책을 16 에서
>      32 로 올린 순간, 재암호화를 위해 읽어야 할 바로 그 행들이 잠긴다.
>    - **관리자 강제 정책인가, 실수 방지 설정인가.** 세션이 마음대로 낮출 수 있다면 후자이고, 전자라고
>      설명해서는 안 된다. 8.0·8.4 에서 GLOBAL 전용이므로 개정 A5 가 이미 답을 제약한다.
>    - **GLOBAL 전용 서버에서 한 애플리케이션 때문에 낮추면 그 서버의 모든 애플리케이션이 절단 보호를
>      잃는다.** 기본값은 기존 배포를 보호하지만, 혼합 배포의 의도를 표현하지는 못한다.
>    - **정책 위반 시의 에러와 설정 조회 실패 시의 동작**을 둘 다 정해야 한다. 후자는 fail closed 가
>      확립된 패턴이다 (개정 A5).
> 2. component 에는 아무것도 두지 않고, 그 기대를 운영 제약으로 문서화한다.
>
> 1번을 권고한다. 이 개정을 기존 배포의 보장을 조용히 약화시키는 것이 아니라 **옵트인**으로 만들기
> 때문이다. 키 정책에 닿는 모든 것에 대해 개정 A8 이 요구하는 대로, 확정 전에 보안 검토가 필요하다.
>
> **의도적으로 범위 밖:** legacy `0x01` 봉투는 AES-256-CBC 로 유지한다. 따라서 지금
> `block_encryption_mode = 'aes-128-cbc'` 로 운영 중인 배포는 여전히 자기 데이터를 dual-read 할 수 없다.
> 이는 실재하는 공백이고 별개의 문제다 — GCM 생성이 아니라 기존 `AES_ENCRYPT` 출력을 읽는 문제다.
> 필요하다면 자체 개정과 자체 version 바이트를 가져야 하고, 여기 묶을 것이 아니라 이관 근거를 보고 결정한다.
>
> **순서.** 0.1.0 태깅 이후 0.2.0 으로 들어간다. 0.1.0 은 봉투가 동결된 상태이고 릴리스 파이프라인을 그에
> 맞춰 드라이런했다. version 바이트 추가는 하위 호환이다 — 모든 0.1.0 봉투가 그대로 복호화되고, 0.1.0
> component 는 `spec/envelope.md` §2.4 가 요구하는 대로 `0x04`~`0x07` 을 `bad_envelope` 로 거부한다 —
> 그러나 스펙 버전이 올라가는 변경이므로 태그를 하나 앞둔 릴리스에 넣을 것이 아니다.
>
> **영향 범위 (구현 PR 용):**
>
> | 영역 | 변경 |
> |---|---|
> | `spec/envelope.md` | v2: 새 version 바이트 4개, version 별 키 길이 표, 불일치 시 `bad_key_len` 규칙 |
> | `spec/test-vectors.json` | AES-128-GCM·AES-192-GCM 의 NIST CAVP KAT (IVlen 96 / Taglen 128) + 새 version 바이트의 자체 벡터 |
> | `src/gcm.{h,cc}` | `crypto_init` 에서 cipher 3개 fetch, 키 길이로 선택, `crypto_deinit` 에서 3개 해제 |
> | `src/envelope.{h,cc}` | 새 version 상수와 각각의 키 길이. 파싱 자체는 변경 없음 |
> | `src/udf_glue.cc` | {16, 24, 32} 수용. 현재 에러 메시지는 32 를 지목한다 |
> | `src/nonce.cc` | 키 길이 검사. 유도식 자체는 변경 없음 |
> | `src/sysvar.{h,cc}` | 완화책 1번을 채택하면 `gcm.min_key_bytes` |
> | `tests/unit` | 세 수트의 KAT, 키 길이 0·15·17·23·25·31·33, version 과 키의 불일치 |
> | `tests/adapter` | `crypto_init` 부분 실패 시 롤백할 핸들이 셋이 된다 |
> | `tests/integration`, `mysql-test` | 수트별 왕복과 한글 LIKE, 불일치 에러 |
> | `tests/bench` | 세 수트를 각자의 맨 EVP 기준 대비로 |
> | README, `docs/ops-constraints.md` | 잘린 키 노출면, 그리고 version 바이트별 수트 |
>
> **이 개정이 답하지 않는 것:**
>
> - 위 완화책 1번인지 2번인지. 보안 검토 대기이며, 1번이라면 함께 적은 네 가지 계약 항목도 포함한다.
> - **새 수트에 nonce 유도의 명시적 도메인 분리가 필요한지.** 레이블이 세 수트에 공유되고, 위의 제로 패딩
>   성질 때문에 짧은 키와 그 제로 확장이 같은 nonce 키를 유도한다. 그 쌍 자체로 공격이 성립하지는 않지만,
>   이 문제는 구현 PR 이 아니라 같은 보안 검토에 속한다.
> - AES-128 에 `gcm_encrypt_det` 를 제공할 것인지. 결정적 nonce 는 수트와 무관하게 HMAC-SHA256 을 96비트로
>   자른 것이므로 §5.2 의 충돌 경계는 키 길이로 바뀌지 않는다 — 그러나 장기 보관 암호문이 존재 이유인
>   구성에서 128비트 키를 쓰는 논거는 물려받을 것이 아니라 명시적으로 세워야 한다.
> - 수트를 SQL 에 노출할 것인지 (예: `gcm_envelope_version(ciphertext)` 헬퍼). 새 공개 함수이므로 자체
>   개정에 속한다.

> ## 개정 A9 (2026-10-02, 확정) — 설치 실패 후 남는 등록과 등록 순서
>
> `INSTALL COMPONENT` 중 `gcm_component_init()` 이 1 을 반환하면, 로더는 롤백하면서
> scope guard 로 scheme 의 `unload` 를 호출하고 그것이 **`dlclose()`** 를 수행한다.
> `dlopen` 에 `RTLD_NODELETE` 가 붙는 것은 **ASan/LSan 빌드뿐**이다
> (`components/libminchassis/dynamic_loader_scheme_file.cc`, 8.4.11 트리에서 확인).
>
> 따라서 롤백에서 해제가 거부된 등록은 **언매핑된 세그먼트**를 가리킨다.
>
> - 해제가 거부된 UDF: `udf_unregister` 는 사용 중인 함수를 **원래 이름 그대로** `udf_hash` 에
>   남긴다 (`sql_udf.cc`). 따라서 이미 resolve 한 세션뿐 아니라 **새 세션이 그 이름을 호출해도**
>   언매핑된 코드로 뛴다. 다만 이름을 알고 호출해야 한다.
> - 해제가 거부된 sysvar: 딕셔너리가 `&g_strict` 를 언매핑 메모리에 두고 있고, **열거만으로**
>   닿는다 — `SHOW VARIABLES`, `performance_schema.global_variables`. 이름을 지목할 필요가 없다.
>
> 즉 차이는 "이미 resolve 했는가" 가 아니라 **지목 대 열거**다. 변수 쪽이 훨씬 도달하기 쉽다.
>
> 결정:
>
> - **component API 로는 고칠 수 없다.** 로더에게 "라이브러리를 매핑된 채 두라" 고 요청하는
>   서비스가 없고, `init` 에서 언로드를 거부할 방법도 없다. 코드로 해결했다고 쓰지 않는다.
> - **등록 순서로 노출을 줄인다.** `gcm.strict` 는 UDF 세 개가 모두 등록된 **뒤에** 등록한다.
>   그러면 실제로 일어날 수 있는 실패(= `udf_register` 가 중간에 실패)의 롤백 시점에는 변수가
>   아직 존재하지 않으므로, 위의 두 번째 경우가 **구조적으로 불가능**해진다. 남는 노출은
>   `sysvar_register()` 자체가 실패하는 경우이고 그때는 UDF 만 되돌린다.
> - 그 대가는 함수가 존재하고 변수가 아직 없는 **짧은 창**이다. 그 창에 들어온 호출은
>   등록되지 않은 변수를 읽어 서비스가 실패하고 `strict_enabled()` 가 `true` 를 돌려준다 —
>   strict **ON**, 즉 fail-closed 방향이다. 창은 `INSTALL COMPONENT` 내부에 있다.
> - 해제가 거부되었을 때 **암호 핸들을 해제하지 않는다.** 이것이 위의 크래시를 막지는 못한다.
>   망가진 설치에 두 번째 결함을 더하지 않는 것, 그리고 `gcm_component_deinit` 과 같은 입장을
>   취하는 것이 목적이다. deinit 에서는 거부된 `UNINSTALL` 이 component 를 로드된 채 두므로
>   같은 추론이 **실제로** 성립한다.
> - **ASan 빌드는 이 결론을 반대로 보이게 한다.** `RTLD_NODELETE` 가 정확히 그때만 붙기
>   때문이다. 이 사안을 샌타이저로 "확인" 하면 틀린 답을 얻는다. `tests/adapter` 의
>   샌타이저가 기본 OFF 인 이유다.
> - **deinit 은 init 의 거울이 아니다.** init 은 변수를 마지막에 등록하지만 deinit 도 변수를
>   마지막에 해제한다 (LIFO 가 아니다). 의도적이다: deinit 은 함수가 사용 중이면 **거부하고
>   되돌려야** 하는데, 변수를 먼저 해제해 두면 거부 시점에 변수가 없는 상태로 component 가 남는다.
>   함수부터 처리하면 거부가 변수에 손대기 전에 일어난다. "대칭이 아니니 맞추자" 는 수정을 하지 않는다.
>   이 순서는 `GivenAFunctionStillInUse_WhenDeinit_ThenTheVariableIsStillRegistered` 와
>   `GivenEverythingUnregisters_WhenDeinit_ThenTheVariableGoesLast` 가 고정한다. 후자는 호출
>   **순서 전체**를 단언한다 — 어떤 호출이 있었는지만 보는 단언은 두 개가 뒤바뀐 것을 보지 못하고,
>   실제로 그 변이가 이 파일의 이전 판을 통과했다.
> - 등록 순서와 롤백 분기는 `tests/adapter/lifecycle_test.cc` 가 스텁 서비스로 고정한다.
>   변이 테스트로 확인한 것: 순서 되돌리기, 조건 없는 자원 해제, `strict_enabled()` 를 fail-open
>   으로 바꾸기, 잠금 없는 `g_strict` 직접 읽기로 되돌리기, `mac_deinit()`·CBC 해제 제거,
>   deinit 의 `was_present` 가드 제거 — 일곱 가지 모두 스위트가 실패한다.

> ## 개정 A8 — 키·nonce 운영 책임과 보안 보장의 범위
>
> component 는 키를 SQL 인자로 받고 nonce 생성·인증 검증을 수행하지만,
> 키별 사용량 집계·자동 키 교체·nonce 중복 탐지·AAD 정책 강제는 구현하지 않는다.
> 배포 전 운영자가 동일 키를 사용하는 모든 서버·컬럼·애플리케이션의 암호화 사용량을
> 합산할 방법과 사용 한도·교체 기준을 정하고 보안 검토를 받아야 한다.
> 무작위/결정적 모드의 충돌 분석과 메시지 길이·위조 시도 등을 함께 고려한다.
> 이 프로젝트는 모든 배포에 적용할 수 있는 안전한 키당 사용량을 확정하지 않았다.
> 근거: [NIST SP 800-38D §8 및 부록 A/B](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).
>
> 결정적 암호화의 AAD 는 컬럼별이 아니라 **동일 키를 사용하는 모든 결정적 호출**에서
> 같은 바이트열(또는 항상 빈 값)이어야 한다. 서로 다른 AAD 영역은 키를 분리한다.
> 암호문 동등성으로 JOIN 하는 컬럼들은 같은 키·AAD 를 사용해야 하며, 키 교체 시
> 이전/신규 암호문의 동등성이 유지되지 않으므로 이관 절차를 함께 설계한다.
>
> 이미 생성한 봉투를 복사·복제·복원하는 것은 새 암호화 호출이 아니다.
> `gcm_encrypt` 재호출은 새 nonce 로 암호화하고, 결정적 재호출은 키·평문·AAD 가
> 모두 같을 때 기존 결과를 재현한다. 재시도 중 AAD 만 바꾸지 않는다.
> 백업 복구로 키 사용량 장부를 되돌리지 않는다. 복구·프로세스 복제 후 난수 상태의
> 안전성이나 누적 사용량을 확신할 수 없으면 해당 키로 새 쓰기를 중단한다. 모든 쓰기 주체의
> 난수 상태를 복구·확인한 뒤 독립적으로 안전하게 생성한 새 키로 쓰기를 재개한다.
> 키 교체만으로 중복된 난수 상태가 해결되는 것은 아니다.
> 과거 데이터/백업 복호화에 필요한 키는 외부 키 관리 절차로 보존한다.
>
> 테스트 벡터 통과와 샘플 nonce 충돌 테스트는 운영 한도 준수나 결정적 구성의 안전성
> 증명이 아니다. 보안 가드 훅도 개발 명령을 제한할 뿐 운영 중 암호 사용을 감시하지 않는다.
> 이 개정은 운영 전제를 명시하며 SQL API·봉투·nonce 유도식·벡터를 변경하지 않는다.

> ## 개정 A8 (2026-09-28) — 배치 토폴로지: ROW 복제와 샤딩
>
> 함수 표면·봉투는 그대로 두고, 이 component 가 **복제·샤딩 구성에서 어떻게 배치되는지**를 명문화한다.
> 결론부터: 샤드마다 primary + ROW replica 를 두는 구성은 이 설계와 자연히 맞는다. 다만 지켜야 할
> 조건이 있고, 그 조건은 코드가 아니라 운영이 지킨다.
>
> **복제 — 암호화 결과를 그대로 전달한다**
>
> - `binlog_format=ROW` 에서는 primary 가 저장한 암호문·nonce·태그가 그대로 복제된다. replica 는
>   암호화를 다시 실행하지 않는다. STATEMENT 방식은 무작위 nonce 때문에 양쪽 값이 달라지므로
>   ROW 를 필수로 둔다 (§6 1항). 근거:
>   <https://dev.mysql.com/doc/refman/8.4/en/replication-formats.html>
>   실측: `tests/e2e/scenarios/replica_consistency.py` 와 `mysql-test/suite/gcm/t/gcm_replication.test`
>   가 양쪽 바이트 일치·replica 복호화·replica 에서의 한글 LIKE 를 확인한다 (8.4 · 9.4 통과).
> - **component 설치는 복제되지 않는다.** `INSTALL COMPONENT` 는 그 서버의 `mysql.component` 에만
>   기록된다. 복호화 조회를 받는 서버, 장애 시 primary 로 승격될 서버에는 **각각 설치**해야 하고,
>   애플리케이션이 그 서버에도 키를 전달할 수 있어야 한다. 근거:
>   <https://dev.mysql.com/doc/refman/8.4/en/component-loading.html>
>   MTR 복제 테스트가 primary·replica 양쪽에서 `gcm_install.inc` 를 소스하는 이유가 이것이다.
>
> **샤딩 — 라우팅과 키 정책이 핵심이다**
>
> | 항목 | 적용할 원칙 |
> |---|---|
> | 샤드 선택 | `tenant_id` 처럼 안정적인 식별자로 라우팅한다. 무작위 nonce 암호문(`0x02`)은 같은 평문도 매번 달라지므로 라우팅 키로 쓸 수 없다. 결정적 암호문(`0x03`)은 안정적이지만 그 자체를 샤드 키로 쓰면 키 로테이션이 리샤딩이 된다 |
> | 샤드 간 데이터 이동 | 기존 암호문을 **그대로** 옮길 수 있다 (재암호화 불필요). 목적지에서도 원래 키와 AAD 로 복호화해야 한다 |
> | 결정적 암호문 비교 | 샤드 간 같은 암호문을 얻으려면 키·평문·AAD 가 모두 같아야 한다. §6 의 "키마다 AAD 하나" 규칙이 샤드 경계를 넘어 적용된다 — 샤드별로 AAD 를 다르게 두면 같은 평문이 다른 봉투가 되어 교차 비교가 깨진다 |
> | 키 사용량 | 같은 키를 여러 샤드에서 쓰면 **새 암호화 호출량을 전체 샤드에 걸쳐 합산**해서 봐야 한다. 기존 암호문을 옮기는 것은 새 암호화가 아니다. 결정적 변형의 nonce 충돌 경계(§5.2)도 이 합산치로 따진다 |
> | 부분일치 검색 | `gcm_decrypt(...) LIKE '%길%'` 만으로는 샤드를 고를 수 없다. 라우팅 조건이 없으면 여러 샤드를 조회하고 각 샤드가 후보 행을 복호화한다 — 비용이 샤드 수에 비례한다 |
>
> **범위 밖**: 특정 샤딩 미들웨어(프록시·라우터)가 사용자 정의 함수 호출을 그대로 전달하는지,
> 결과 charset 을 보존하는지는 **그 조합으로 따로 검증해야 한다.** 이 저장소는 자체 운영 MySQL 서버에
> 대해서만 검증한다 (§0 범위). 프록시 방식은 §0 에서 이미 범위 밖이다.

> ## 개정 A7 (2026-09-28, 확정) — 계산된 SQL 식을 인자로 넘기지 않는다 (8.0·8.4 서버 결함)
>
> MySQL 8.0·8.4 는 **계산된 문자열 식**을 loadable function 인자로 넘길 때, 한 statement 의
> **두 번째 행부터** 낡은 인자 뷰를 건네준다. 같은 식을 빌트인 함수에 넘기면 항상 올바른 값이
> 나오고, component 를 "인자를 그대로 되돌려주는" 빌드로 바꿔도 같은 손상이 관측된다 —
> 즉 component 안에서는 탐지도 복구도 불가능하다. 9.4.0 에서는 재현되지 않는다.
>
> 실측 (`tests/integration/91_server_udf_arg_defect.sql` 이 버전별로 고정한다):
>
> | 인자 식 | 8.0.43 | 8.4.11 | 9.4.0 |
> |---|---|---|---|
> | `CONCAT(col, int_col)` · `CONCAT_WS(...)` · 이를 감싼 `LOWER(...)` | 정상 | **byte 0 손상** | 정상 |
> | `REPEAT('a', int_col)` | **길이 부풀림** | 정상 | 정상 |
> | `CAST(계산식 AS CHAR)` | 정상 | **16바이트에서 손상** | 정상 |
> | 컬럼 · 리터럴 · 사용자 변수 · 바인드 파라미터 | 정상 | 정상 | 정상 |
>
> 원인 지점은 `sql/item_func.cc` 의 `udf_handler::get_and_convert_string` 이다. 인자 Item 이 돌려준
> `String` 을 **얕게 복사**한 뒤(`buffers[index] = *res`) `c_ptr_safe()` 를 호출하는데, 그 Item 이
> 중첩 Item 의 버퍼를 가리키고 있으면 포인터·길이가 낡는다. 8.4 의 손상이 16바이트 경계에서
> 나타나는 것이 `String` 재할당 경계와 일치한다.
>
> 결정:
>
> - **회피를 코드로 시도하지 않는다.** 서버가 변환을 수행하도록 다른 collation 을 요구하면
>   (`argument_set(args, "collation", 0, "utf8mb4_bin")`) 8.4 의 `CONCAT` 손상은 사라지지만
>   `REPEAT` 의 **길이**가 부풀어 더 나쁜 결과(더 많은 바이트를 봉인)가 된다. 실측으로 확인했다.
>   따라서 `udf_encrypt.cc` 는 계약이 요구하는 charset(`utf8mb4`)만 요청한다.
> - **운영 제약으로 문서화한다** (§6, `docs/ops-constraints.md` 10항, README). 모든 버전에서 안전한
>   호출 형태는 컬럼·리터럴·사용자 변수·바인드 파라미터, 즉 **구체화된 값**이다. 애플리케이션이
>   드라이버로 바인드 파라미터를 보내는 정상 경로는 영향이 없다.
> - SQL 안에서 값을 계산해야 하면 **실제 테이블**에 먼저 쓴다 (`CREATE TEMPORARY TABLE ... AS SELECT`
>   또는 별도 statement) 뒤 저장된 컬럼으로 호출한다. **파생 테이블은 안 된다**: 기본
>   `derived_merge=on` 에서 옵티마이저가 파생 테이블의 식을 바깥 쿼리로 병합하므로 결국 행마다 계산된다.
>   8.4.11 실측 — `FROM (SELECT CONCAT(nm,id) AS v FROM t) d` 는 2·3행이 손상되고, 같은 쿼리에
>   `/*+ NO_MERGE(d) */` 또는 `derived_merge=off` 를 주면 정상이다. 그 둘은 구체화를 강제하므로 동작하지만
>   옵티마이저 힌트라 장래 버전이 무시할 수 있다. 실제 테이블은 그렇지 않다.
>   `CAST` 만으로도 충분하지 않다 (8.4, 16바이트).
> - `gcm_decrypt` 의 봉투 인자도 같은 부류이지만 실패가 `bad_tag`/`bad_envelope` 에러로 드러나므로
>   조용한 데이터 손상이 아니다. `gcm_encrypt*` 가 위험한 쪽이다.
> - 서버가 수정되면 91 케이스의 기대값이 0→1 로 바뀌어 CI 에서 드러난다. 그때 이 개정과 제약을 해제한다.

> ## 개정 A6 — 모듈 경계와 자원 수명
>
> 배포 범위(A4)와 SQL·봉투 계약은 유지하고, 구현의 경계를
> `.agents/rules/architecture.md` 에 명문화한다. 서버 어댑터는 코어를 호출하지만
> 코어(`gcm`, `envelope`, `nonce`)는 MySQL 서비스·설정·SQL 오류에 의존하지 않는다.
> SQL NULL·charset·strict 오류 변환은 UDF 계층, 바이트 형식은 envelope,
> 인증 결과는 gcm, 서버 버전 차이는 component/sysvar 계층이 담당한다.
>
> 자원은 component·UDF_INIT·연산 수명으로 구분한다. UDF_INIT 은 세션 전체와
> 동일하지 않다. (개정 A11 은 비밀을 담는 자원 둘 — `gcm_decrypt` 의 스케줄된 EVP 컨텍스트와
> `gcm_encrypt_det` 의 유도된 nonce 키, 각각 키 복사본과 함께 — 를 거기 적은 불변 조건 아래
> UDF_INIT 수명에 추가한다.) 등록 실패 시 롤백하고, 해제 실패 시 사용 중인 자원을 유지하며
> 이미 해제한 자원을 다시 해제하지 않도록 상태를 추적한다.
> 행 처리 경로에서 설정 조회·알고리즘 fetch·파일/네트워크 접근을 반복하지 않는다.
> 테스트용 고정 nonce 진입점은 SQL 에 노출하지 않고, 암호화를 우회하는 실험 코드는
> 배포 대상에서 제외한다. 기존 파일 배치를 유지하며 범용 backend 계층은 추가하지 않는다.
>
> 참고한 구현: [Percona Encryption UDF](https://github.com/percona/percona-server/blob/8.4/components/encryption_udf/encryption_udf_component.cc)의
> 서버/암호 래퍼 분리와 등록 상태 추적,
> [MySQL keyring operations](https://dev.mysql.com/doc/dev/mysql-server/8.4.9/operations_8h_source.html)의
> 연산/backend 경계,
> [pgcrypto SQL 진입점](https://github.com/postgres/postgres/blob/REL_17_STABLE/contrib/pgcrypto/pgcrypto.c)의
> SQL 인자·결과·오류 변환. 이들은 설계 참고이며 외부 프로젝트의 API·예외 정책·기능을 도입하는 근거는 아니다.

> ## 개정 A5 (2026-09-28, 확정) — `gcm.strict` 의 SESSION 스코프는 MySQL 9.0+ 에서만
>
> A1 개정은 `gcm.strict` 를 GLOBAL + SESSION 으로 두었다. 서버 소스 실측 결과
> **component sysvar 의 세션 스코프는 9.0.0 이상에만 구현되어 있다.** 8.0/8.4 에서
> `PLUGIN_VAR_THDLOCAL` 을 넘기면 등록은 성공하고 값 읽기는 범위 밖 읽기가 된다.
>
> 근거 (태그 `mysql-8.0.43` · `mysql-8.4.11` · `mysql-9.4.0` 실측):
>
> - `sql/server_component/component_sys_var_service.cc` 의 `PLUGIN_VAR_THDLOCAL` 등장 횟수는
>   8.0.43 · 8.4.11 이 0, 9.4.0 이 11 이다. 8.x 의 `register_variable` 은
>   `flags & PLUGIN_VAR_WITH_SIGN_TYPEMASK`(`0x00ff`) 로만 타입을 분기하므로 THDLOCAL(`0x0100`)이 탈락하고,
>   전역 bool 포인터를 쓰는 GLOBAL 경로가 실행된다.
> - 그런데 `sys_var_pluginvar` 는 **그 플래그로 스코프를 정하고**(`sql/sql_plugin_var.h`),
>   값 접근은 `real_value_ptr()` 에서 `*(int *)(plugin_var + 1)` 을 세션 저장소의 **바이트 offset** 으로
>   해석한다(`sql/sql_plugin_var.cc`). 8.x component 경로에서 그 자리는 전역 변수의 주소다 → OOB read.
>   **8.0/8.4 에 THDLOCAL 을 넘기지 않는다.**
> - 세션 값을 읽는 유일한 서비스 `mysql_system_variable_reader` 도 9.0.0 신설이다
>   (`include/mysql/components/services/mysql_system_variable.h`: 8.4.11 부재, 9.4.0 존재).
>   `component_sys_variable_register::get_variable` 은 헤더 주석과 구현(`OPT_GLOBAL` 하드코딩) 모두
>   **GLOBAL 전용**이라 세션 값 읽기에 쓸 수 없다.
> - 9.x 선례: `components/test/test_session_var_service.cc`,
>   `mysql-test/suite/service_sys_var_registration/{t,r}/session_var_service.*`.
>
> 결정:
>
> ```
> MySQL 9.0+     gcm.strict : GLOBAL + SESSION   (PLUGIN_VAR_BOOL | PLUGIN_VAR_THDLOCAL)
> MySQL 8.0/8.4  gcm.strict : GLOBAL only        (PLUGIN_VAR_BOOL)
> ```
>
> - 분기는 **컴파일 타임** (`MYSQL_VERSION_ID`). `mysql_system_variable_reader` 의 `SERVICE_TYPE` 선언
>   자체가 8.x 헤더에 없어 런타임 probe 로는 빌드되지 않고, `REQUIRES_SERVICE` 는 하드 로드 의존이므로
>   8.x 빌드에서는 그 두 서비스를 REQUIRES 목록에서 빼야 한다.
> - 8.0/8.4 에서 `SET SESSION gcm.strict` 는 서버가 `ER_INCORRECT_GLOBAL_LOCAL_VAR` 로 거부한다.
>   §6 운영 제약과 README 에 명시한다.
> - **태그 실패 의미론은 바뀌지 않는다** (ON=에러, OFF=NULL). 바뀌는 것은 그 값을 어느 스코프에서
>   바꿀 수 있는지 뿐이다. 서비스 호출 실패 시에는 strict ON 으로 간주한다 (fail closed).
> - 값은 statement 당 한 번(`Udf_func_init`)만 읽고 행마다 읽지 않는다. reader 는
>   `LOCK_system_variables_hash` read lock + 해시 룩업 + 숫자→문자열 변환을 거치므로 행 단위 호출은
>   부하 게이트에서 바로 드러난다. `SET SESSION` 은 statement 경계에서만 바뀌므로 의미론도 정확하다.

> ## 개정 A4 — 배포 범위는 MySQL component 와 SQL 인터페이스
>
> Python·Java 암호화 클라이언트를 별도 제품으로 제공하지 않는다. 애플리케이션은
> 기존 MySQL 드라이버로 `gcm_encrypt` / `gcm_encrypt_det` / `gcm_decrypt` 를 SQL 호출한다.
> 드라이버에 이 프로젝트의 암호 구현을 통합할 필요는 없다.
>
> Python 은 벡터 생성·검증과 SQL 기반 E2E/부하 실행을 위한 개발 도구로만 사용한다.
> `scripts/gen-vectors.py` 는 `cryptography` 로 고정 입력의 벡터를 생성하고 검증하며,
> 재사용 가능한 암복호화 클라이언트 API 나 패키지를 제공하지 않는다.
> 봉투·SQL API·기존 벡터의 바이트 값은 이 범위 개정으로 변경하지 않는다.
> C++ 단위 테스트와 SQL 통합 테스트가 서버 동작을 검증하며, 언어별 클라이언트의
> 동등성 검증·배포·호환성 유지 의무는 제거한다.

> ## 개정 A2 (2026-09-28, 확정) — 결정적 봉투도 nonce 를 저장한다
>
> 미해결 이슈 A2 를 다음으로 확정한다. §2.2 는 결정적 봉투를 `version || ct || tag` 로 두고
> "nonce 는 재계산" 이라 했지만, nonce 가 평문의 HMAC 이므로 **복호화 시점에는 평문을 몰라
> 재계산할 수 없다.** 따라서 결정적 봉투도 nonce 12 바이트를 저장한다.
>
> ```
> 0x02  GCM 무작위 : 0x02 || nonce(12) || ciphertext || tag(16)
> 0x03  GCM 결정적 : 0x03 || nonce(12) || ciphertext || tag(16)   # nonce 는 유도하되 저장한다
> ```
>
> - 결정성·동등성은 그대로다 (같은 키·평문·AAD → 같은 봉투 전체 바이트). 조인·UNIQUE 는 영향 없음.
> - 비용: 결정적 값당 +12 바이트. §2.2 의 "실제 증가 0~16 바이트" 는 **"평문 + 29 바이트"** 로 정정한다.
> - 복호화는 저장된 nonce 를 그대로 쓴다. 재계산 후 비교는 요구하지 않는다 (GCM 태그가 이미 인증한다).
> - 대안 AES-GCM-SIV 는 OpenSSL 3.2+ 에 묶여 서버 OpenSSL 을 제약하므로 채택하지 않는다.
>   선례는 HashiCorp Vault Transit 의 convergent encryption v2 (nonce 를 함께 저장한다).
> - 확정본은 `spec/envelope.md` (FINAL). 서버 구현·벡터 생성 도구·테스트는 그 문서를 따른다.

> ## 개정 A3 (2026-09-28) — v1 legacy CBC 봉투의 정의
>
> §2.2 는 version 바이트로 CBC→GCM dual-read 를 지원한다고만 했고 v1 의 바이트 배치는 비어 있었다.
> 구현·테스트를 위해 다음으로 정의한다. **복호화 전용이며 component 는 v1 을 절대 생성하지 않는다.**
>
> ```
> 0x01  legacy CBC : 0x01 || iv(16) || AES-256-CBC(PKCS#7) ciphertext
> ```
>
> - 마이그레이션은 기존 `AES_ENCRYPT` 값 앞에 version 바이트와 IV 를 덧붙이기만 한다 — 재암호화가 없다.
>   MySQL 은 32 바이트 키를 그대로 AES-256 키로 쓴다 (`my_aes_create_key` 의 XOR 접기는 입력 길이가
>   키 길이와 같으면 항등이다). 따라서 같은 키로 `gcm_decrypt` 와 `AES_DECRYPT` 결과가 같다.
> - v1 은 **인증되지 않는다.** 틀린 키로도 패딩이 우연히 맞으면 쓰레기 평문이 나올 수 있다. legacy
>   데이터의 성질이며 v2/v3 로 이관하면 사라진다. 이 한계를 `spec/envelope.md` 와 README 에 명시한다.
> - v1 은 AAD 를 받지 않는다. 비어 있지 않은 AAD 로 v1 을 복호화하면 `bad_envelope` 에러.
> - `gcm.strict` 는 v1 경로에 영향을 주지 않는다 (태그가 없다). 길이·패딩 오류는 항상 에러.

> ## 개정 A1 (2026-09-28) — 키 전달 방식: keyring → SQL 인자
>
> 초기안(§2.1 · §2.3 · §3 · §5.4 · Phase S 의 keyring 항목)과 달리, **키는 기존 MySQL
> `AES_ENCRYPT(str, key_str)` 과 동일하게 SQL 인자로 받는다.** 아래가 §2 를 대체한다.
>
> ```
> gcm_encrypt(plaintext, key [, aad])       -> BLOB     무작위 nonce
> gcm_encrypt_det(plaintext, key [, aad])   -> BLOB     결정적
> gcm_decrypt(ciphertext, key [, aad])      -> VARCHAR  charset 태깅 (utf8mb4)
> ```
>
> - `key` 는 **정확히 32 바이트**(AES-256) 바이너리. 길이가 다르면 에러. `AES_ENCRYPT` 의
>   키 접기(XOR folding)는 재현하지 않는다 — 약한 키를 조용히 받아들이는 원인이다.
> - 결정적 변형의 nonce 키는 별도 인자 없이 도메인 분리로 유도한다 (Phase 1 에서 확정):
>   `nonce_key = HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")`,
>   `nonce = HMAC-SHA256(nonce_key, plaintext)[:12]`.
> - sysvar 는 `gcm.strict` (GLOBAL + SESSION, 기본 ON) 만 남는다. my.cnf 에는 `loose_gcm.strict`.
>   `gcm.key_id` · `gcm.nonce_key_id` · `gcm_key_id()` 는 폐기.
> - `keyring_reader_with_status` 의존과 §3 keyring 백엔드 선결 결정은 **범위 밖**이 된다.
>   §5.4 의 "키를 my.cnf 에 두지 않는다" 는 여전히 유효하다 (키는 앱이 보관하고 쿼리마다 전달).
> - 대가: 키 바이트가 SQL 문에 등장하므로 general log · slow log · `performance_schema.events_statements_*`
>   · SBR binlog 에 남을 수 있다. 이는 **현재 `AES_ENCRYPT` 운영과 동일한 노출면**이며 §6 운영 제약에
>   추가한다. keyring 방식은 향후 선택 기능(`gcm_encrypt_kr` 류)으로 재검토할 수 있다.
> - Phase S 체크리스트에서 "keyring 에서 키를 읽음" 항목은 제거되고, "32 바이트 키 인자 검증 +
>   `SET SESSION gcm.strict` 동작" 으로 대체된다.

MySQL 에 AES-256-GCM 암복호화 함수를 추가하는 서버 component 를 만들기 위한
설계 문서. 별도 오픈소스로 분리할 것을 전제로 쓴다.

암호화 로드맵 2단계(CBC→GCM)의 선택 가능한 구성요소다. 이것 없이도 GCM 전환은
가능하지만, 그 경우 서버측 검색(LIKE)을 잃는다 — §1 참조.

> 원 프로젝트의 관련 문서: `.agents/docs/value-column-encryption.md`(로드맵),
> `.agents/docs/ope-removal.md`(0단계). 이 저장소에는 포함되지 않는다.

## 0. 목표와 범위

| 항목 | 내용 |
|---|---|
| 목표 | MySQL 에 GCM 암복호화 함수 추가 + my.cnf 통합 + 복호화 후 LIKE 검색 |
| 형태 | MySQL 8.0+ component (legacy UDF plugin 아님 — §5.1) |
| 대상 | 자체 운영 MySQL 만. 관리형(RDS·Aurora·Cloud SQL)은 설치 불가 |
| 범위 밖 | 프록시 방식, 언어별 암호화 클라이언트/SDK, DB 드라이버 통합, 키 관리 시스템 자체 |

## 1. 왜 필요한가

### 1.1 MySQL 은 GCM 을 지원하지 않는다 (확정)

`block_encryption_mode` 허용값은 `aes-{128,192,256}-{ECB,CBC,CFB1,CFB8,CFB128,OFB}`
뿐이고, AEAD 모드가 없다. 인증 태그·AAD 를 받을 인자 자리도 없다.

실측 — 컨테이너에서 `SET SESSION block_encryption_mode` 직접 시험:

| 모드 | MySQL 8.4.11 | MySQL 9.4.0 |
|---|---|---|
| aes-256-cbc / -ecb / -cfb128 / -ofb | 수용 | 수용 |
| aes-256-gcm | 거부 | 거부 |
| aes-256-gcm-siv / -siv / -ctr / -xts | 거부 | 거부 |

```
ERROR 1231 (42000): Variable 'block_encryption_mode' can't be set to the value of 'aes-256-gcm'
```

문서도 8.0 → 8.4 → 9.7 까지 같은 목록이다. MySQL 버전을 올려 해결하는 경로는 없다.
MariaDB 도 ECB/CBC/CTR 뿐이라 계열 전체의 한계다.

### 1.2 서버측 복호화를 잃으면 부분일치 검색이 성립하지 않는다

환자명·EMR ID 부분일치 검색은 현재 서버측 `AES_DECRYPT + LIKE` 로 동작한다.
이를 앱으로 옮기면 요청마다 후보 전량을 복호화해야 한다.

| 후보 환자 수 | 앱측 읽기 + 복호화 (실측 기준 10.6µs/행) |
|---|---|
| 10,000 | 117ms |
| 100,000 | ~1.1초 |
| 300,000 | ~3.2초 |

검색 요청마다 3초는 성립하지 않는다. 서버측은 행 전송·파이썬 객체 생성이 없고
암복호가 C 속도라 비용 구조가 근본적으로 다르며, 현재 운영이 이미 그렇게 돌고
있으므로 성립이 증명된 경로다.

> 부분일치를 포기할 수 있다면(전방일치·정확일치로 축소) 이 component 는 필요 없다.
> 제품 결정이 선행 조건이다.

### 1.3 기존 오픈소스로는 안 된다

| 프로젝트 | 상태 |
|---|---|
| crypsi-mysql-udf | AES-GCM UDF 를 제공하지만 스타 0 · 커밋 36 · OpenSSL 1.1.1(EOL) 요구 · 키를 SQL 인자로 받음 · 결정적 모드 없음 · 라이선스 불명확 |
| lib_mysqludf_aes256 | AES-256 확장이고 GCM 아님 |
| Acra (Apache 2.0) | 프록시로 AES-256-GCM. 검색은 정확일치만(CE), 전방일치는 Enterprise, 부분일치·범위 없음. SQL 파싱 프록시라 CTE 많은 쿼리에 리스크 |

Acra 의 기능 경계가 우리 진단을 독립적으로 확인해준다 — 이 분야 제품도 부분일치는
제공하지 않는다.

## 2. 무엇을 만드는가

> 키 취급은 개정 A1 이, 봉투는 A2·A3 이 대체했다. 아래 원문을 그대로 두는 이유는 그 개정들이 바로 이
> 텍스트에 대한 델타로 쓰여 있어 원문 없이는 읽히지 않기 때문이다. **현행 설계가 아니다** — `gcm_key_id()`,
> 키 인자 없는 함수 표면, nonce 를 저장하지 않는 결정적 봉투는 모두 폐기됐다.

### 2.1 함수 표면

빌트인을 덮어쓸 수 없으므로 새 이름이어야 한다. `block_encryption_mode` 에
모드를 추가하는 것도 불가능하다.

```
gcm_encrypt(plaintext [, aad])       -> BLOB      무작위 nonce
gcm_encrypt_det(plaintext [, aad])   -> BLOB      결정적 (조인·UNIQUE·정확일치용)
gcm_decrypt(ciphertext [, aad])      -> VARCHAR   charset 태깅 (§5.3)
gcm_key_id()                         -> VARCHAR   현재 key id (관측용)
```

`gcm_encrypt_det` 는 선택이 아니다. 이것이 없으면 암호 컬럼을 조인 키로 쓰는
지점 전체가 깨진다 (vc-backend 94 / vc-report 37 / vc-sync 88곳, 패턴 재산정치).
결정적 변형이 있으면 그 지점들은 무변경이다.

```
nonce = HMAC-SHA256(nonce_key, plaintext)[:12]     # 합성 nonce, 저장 불필요
ct    = AES-256-GCM(key, nonce, plaintext, aad)
```

### 2.2 암호문 봉투

```
무작위 nonce : version(1) || nonce(12) || ciphertext || tag(16)
결정적       : version(1) || ciphertext || tag(16)        # nonce 는 재계산
```

- BLOB 반환. VARCHAR 아님 — MySQL 은 바이너리를 텍스트 형식으로 필터할 때
  동작이 애매하다 (Acra 도 같은 이유로 명시적 캐스팅을 넣었다)
- version 바이트로 CBC(v1) → GCM(v2) 과도기 dual-read 를 지원한다
- PKCS7 패딩이 사라지므로 실제 증가는 0~16바이트 (결정적 변형 기준)

### 2.3 my.cnf 통합

`component_sys_variable_register` 로 sysvar 를 등록하면 my.cnf·커맨드라인에서 설정된다.

```ini
[mysqld]
# key id 만. 키 바이트는 절대 두지 않는다 (§5.4)
loose_gcm.key_id       = vc_phi_v1
loose_gcm.nonce_key_id = vc_phi_nonce_v1
loose_gcm.strict       = ON
```

| sysvar | 스코프 | 설명 |
|---|---|---|
| gcm.key_id | GLOBAL + SESSION | keyring data id. 세션 스코프가 있어야 로테이션·dual-read 과도기가 된다 |
| gcm.nonce_key_id | GLOBAL + SESSION | 합성 nonce 용 HMAC 키 id (암호 키와 분리) |
| gcm.strict | GLOBAL + SESSION | 태그 불일치 시 ON=에러 / OFF=NULL |

키는 `keyring_reader_with_status` 로 Data ID 조회한다 → 키 바이트가 SQL 에
등장하지 않는다. crypsi 의 결함을 이걸로 피한다.

## 3. 선결 결정 — keyring 백엔드 (스파이크보다 먼저)

> 개정 A1 으로 **범위 밖**이 됐다. A1 이 이 절을 근거로 쓰여 있어 남겨둔다.

이 결정이 프로젝트 정당성 자체를 좌우한다.

지금은 앱이 키를 갖고 SQL 로 넘긴다. keyring 방식은 DB 호스트에 키가 상주한다.

로드맵이 밝힌 암호화의 실질 효익은 "DB 파일·백업 유출 시 값 노출 차단" 이다.
그런데 `component_keyring_file` 로 같은 호스트에 키를 두면 데이터 파일을 가져간
사람이 키도 가져간다 — 그 효익이 사라진다.

| 백엔드 | 판정 |
|---|---|
| component_keyring_file | 불가. 위 효익이 무너진다. 개발·테스트에만 |
| component_keyring_vault / KMS keyring | 필요 조건 |

외부 keyring 을 운영에 둘 수 없다면 이 방향 전체를 재검토해야 한다.
"keyring_file 로 시작해서 나중에 바꾼다"는 계획은 위험하다.

## 4. 절차

### Phase S — 스파이크 (1~2일, 스펙보다 먼저)

위험한 미지값을 한 번에 답하는 최소 component 를 먼저 만든다. 이 결과에 따라
스펙이 달라지므로 순서를 바꾸지 않는다.

- [ ] component 골격이 UDF 하나를 `mysql_service_udf_registration` 으로 등록
- [ ] my.cnf 의 `loose_gcm.key_id` 를 sysvar 로 읽음
- [ ] keyring 에서 그 id 로 키를 읽음 (`keyring_reader_with_status`)
- [ ] `gcm_decrypt` 반환값에 charset 태깅 → 한글 `LIKE '%김%'` 이 native collation 으로 동작
      ← decrypt_like 필요 여부가 여기서 결정된다 (§5.3)
- [ ] `Created_tmp_disk_tables` 관측 — 평문이 디스크 temp 로 내려가는지 (§5.3)
- [ ] `EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)` 이 빌드·런타임 OpenSSL 조합에서 성공

로컬 검증:

```sh
# 빌드한 .so 를 plugin_dir 로 넣고
docker cp component_gcm.so mysql-dev:/usr/lib/mysql/plugin/
docker exec -i mysql-dev mysql -uroot <<'SQL'
INSTALL COMPONENT 'file://component_gcm';
SELECT gcm_key_id();
SELECT HEX(gcm_encrypt_det('홍길동'));
SELECT gcm_decrypt(gcm_encrypt_det('홍길동'));
SELECT gcm_decrypt(gcm_encrypt_det('홍길동')) LIKE '%길%';   -- 1 이어야 한다
SHOW STATUS LIKE 'Created_tmp_disk_tables';
SQL
```

### Phase 1 — 스펙 (스파이크 결과 반영 후)

- 봉투 포맷 · 함수 표면 · sysvar · 실패 의미론 확정
- 테스트 벡터 — NIST CAVP GCM KAT + 자체 벡터. C++ 서버 코어와 SQL 테스트의 공통 기준이다
- 문서화할 운영 제약 목록 (§6)

### Phase 2 — 구현 + 테스트

- OpenSSL EVP, 이름으로 fetch (`EVP_aes_256_gcm()` 심볼 직접 사용 금지 — 빌드 OpenSSL 에 묶인다)
- `OPENSSL_cleanse` 로 키 버퍼 소거. 에러 메시지에 키·평문 금지
- MTR (mysql-test) .test/.result 스위트
- 결정적 변형의 nonce 충돌 경계 테스트

### Phase 3 — SQL 사용 흐름과 E2E 검증

기존 MySQL 드라이버로 SQL 함수를 호출하는 사용 흐름을 검증한다. 암호화 저장 →
서버 복호화와 한글 LIKE, ROW 복제, legacy CBC dual-read, AAD 불일치 및 세션 strict
격리를 다룬다. Python runner 는 SQL 실행·결과 확인만 담당하며 암복호화하지 않는다.

### Phase 4 — 빌드·배포·문서

- 빌드 매트릭스: MySQL 메이저 버전 × 플랫폼(amd64/arm64, glibc/musl) × OpenSSL
  — component ABI 가 서버 버전에 결합된다
- §6 의 운영 제약을 README 첫 화면에 배치

### Phase 5 — 업스트림 (선택, 기대치 낮게)

선례: WL#6781 "Support multiple AES Encryption modes" 가 지금의 모드 목록을 추가했다.
채널은 존재한다.

다만 `AES_ENCRYPT(str, key, iv, kdf, salt, info)` 에 태그·AAD 자리가 없어 기존 함수
확장이 아니라 새 함수군이 필요하므로 수용 가능성은 낮다. feature request 제출은
비용이 거의 없다.

## 5. 설계 결정과 근거

### 5.1 왜 component 인가 (legacy UDF plugin 아님)

component 인프라는 서비스 경계가 명확하고 신규 확장의 권장 경로다. 결정적으로
keyring 서비스와 sysvar 등록 서비스를 쓸 수 있다 — legacy UDF 로는 키를 함수
인자로 받는 수밖에 없다 (crypsi 가 그렇다).

### 5.2 왜 결정적 변형이 필수인가

암호 컬럼이 스키마의 조인 백본이다.

```
Patient.encrypted_emr_id      == Encounter.encrypted_patient_id
Encounter.encrypted_emr_id    == Score.encrypted_encounter_id
Encounter.encrypted_emr_id    == UserPin.encrypted_encounter_id
```

또 `uq_emr_location_natural_key (site, ward, room, bed)` 는 room/bed 가 결정적
AES 라서 성립하는 UNIQUE 다. 무작위 nonce 만 제공하면 이 전부가 깨진다.

합성 nonce 의 안전성: 서로 다른 평문이 같은 nonce 를 얻으면 GCM 은 치명적이지만,
HMAC-SHA256 을 96비트로 자른 충돌은 값 1,000만 개 기준 약 10⁻¹⁵ 수준이다. 같은
평문이 같은 nonce 를 얻는 것은 의도한 결정성이다. 다만 동일 키의 모든 결정적 호출에서
AAD 가 같아야 한다(개정 A8). 동등성·빈도·길이 정보가 노출되며, 이 충돌 확률 계산만으로
구성 전체의 안전성이나 키당 운영 한도가 증명되지는 않는다. 별도 보안 검토가 필요하다.

선례: HashiCorp Vault Transit 의 convergent encryption 이 같은 구성이다.

### 5.3 왜 decrypt_like 를 먼저 만들지 않는가

MySQL 8.0.19 부터 `mysql_udf_metadata` 서비스로 반환값의 charset/collation 을
지정할 수 있다. 그러면 MySQL 의 native LIKE 를 그대로 쓸 수 있다.

```sql
WHERE gcm_decrypt(encrypted_name) LIKE '%김%'   -- utf8mb4_general_ci 로 동작
```

decrypt_like 를 직접 만들면 C 로 utf8mb4_general_ci 의 대소문자 무시·유니코드
정규화 의미론을 CJK 까지 재현해야 한다. OPE 제거에서 파이썬 코드포인트 순서와
MySQL collation 이 달라 한 번 데인 지점이다. 재현하지 말고 MySQL 것을 쓴다.

> 단, decrypt_like 를 원할 정당한 이유가 하나 있다 — 성능이 아니라 보안이다.
> `gcm_decrypt(col)` 이 임시 테이블·filesort 를 타면 평문이 디스크 기반 temp 로
> 내려간다. boolean 만 돌려주는 융합 함수는 평문을 메모리 밖으로 내보내지 않는다.
> Phase S 에서 `Created_tmp_disk_tables` 로 실제 발생을 관측한 뒤 판단한다.

### 5.4 왜 키를 my.cnf 에 두지 않는가

파일 읽기 권한자 전원에게 노출되고, 설정관리·백업·이미지에 남고, SHOW VARIABLES
로도 보일 수 있다. MySQL 자신의 InnoDB TDE 가 쓰는 방식이 정답이다 — my.cnf 는
key id 만, 키 바이트는 keyring.

### 5.5 태그 불일치를 NULL 로 내리지 않는다

기존 `AES_DECRYPT` 는 실패 시 NULL 을 돌려줘 "키 틀림"과 "데이터 없음"이 구분되지
않는다. AEAD 에서 이건 인증의 의미를 없앤다. `gcm.strict=ON` 을 기본으로 두고
에러를 올린다.

## 6. 운영 제약 — README 에 반드시 명시

- 무작위 nonce 함수는 비결정적 → statement-based replication 에서 위험하다.
  `INSERT ... VALUES(gcm_encrypt(...))` 가 마스터와 레플리카에서 다른 값을 만든다.
  ROW binlog 필수
- 비결정 함수는 생성 컬럼·인덱스에 사용 불가
- 평문이 서버 로그에 남는다. 암호화 호출은 평문을 SQL 인자로 받으므로 general
  log · slow log · performance_schema.events_statements_* · SBR binlog 에 남는다.
  검색 패턴('%김%')도 평문 PHI 조각이다. UDF 방식의 근본 한계이며 회피할 수 없다
- 관리형 MySQL 에는 설치할 수 없다 (plugin_dir 접근 불가)
- component sysvar 는 component 설치 전까지 값이 적용되지 않는다. my.cnf 에
  `loose_` 접두 없이 적으면 최초 기동이 실패할 수 있다
- UDF 는 옵티마이저에 불투명하다. 선택도는 다른 술어(scope·status 필터)에 의존한다
- (개정 A2) `gcm_encrypt_det` 의 nonce 는 평문만의 함수다. **한 키에 대해 같은 평문을 서로 다른 AAD 로
  암호화하면 (키, nonce) 쌍이 재사용**되고, 두 값을 모두 본 공격자는 GHASH 서브키를 복원해 그 nonce 에
  대한 태그 위조가 가능해진다. 기밀성은 영향받지 않는다(같은 평문이므로 키스트림이 두 평문을 덮지 않는다).
  운영 규칙: 동일 키를 사용하는 모든 결정적 호출에서 AAD 를 하나로 고정한다.
  서버·컬럼·애플리케이션이 달라도 예외가 없으며, 다른 AAD 영역에는 다른 키를 쓴다.
  무작위 변형에는 이 AAD 고정 제약이 적용되지 않는다.
  근거·표현은 `spec/envelope.md` §3.
- (개정 A3) `gcm_decrypt` 는 legacy `0x01`(CBC) 봉투를 받아들이며 이 경로는 **인증되지 않는다**.
  dual-read 이관이 끝나면 애플리케이션에서 `0x01` 을 거부한다.
- (개정 A1) 키가 SQL 인자로 전달되므로 general log · slow log · performance_schema · SBR binlog 에
  키 바이트가 남을 수 있다. `AES_ENCRYPT` 와 동일한 노출면. general log 비활성, slow log 의
  `log_raw=OFF` 는 도움이 되지 않으므로(UDF 인자는 리터럴) 로그 접근 통제로 대응한다
- (개정 A5) `gcm.strict` 는 MySQL 9.0 미만에서 **GLOBAL 전용**이다. 8.0·8.4 에서 `SET SESSION gcm.strict`
  는 `ER_INCORRECT_GLOBAL_LOCAL_VAR` 로 거부된다. 태그 실패 의미론(ON=에러, OFF=NULL)은 모든 버전에서 같다
- (개정 A7) **계산된 SQL 식을 `gcm_encrypt*` 인자로 직접 넘기지 않는다.** 8.0·8.4 서버가 두 번째 행부터
  낡은 인자를 건네 조용히 잘못된 평문을 봉인할 수 있다. 컬럼·리터럴·사용자 변수·바인드 파라미터를 쓰고,
  SQL 안에서 계산해야 하면 먼저 구체화한다 (`CAST` 만으로는 불충분)
- (개정 A8) **component 설치는 복제되지 않는다.** 복호화 조회를 받는 서버와 승격 대상 replica 에 각각
  `INSTALL COMPONENT` 하고, 애플리케이션이 그 서버에도 키를 전달할 수 있어야 한다. ROW binlog 는
  암호문·nonce·태그를 그대로 옮기므로 replica 가 재암호화하지 않는다
- (개정 A8) **샤딩에서는 무작위 암호문을 라우팅 키로 쓸 수 없고**, `gcm_decrypt(...) LIKE` 만으로는
  샤드를 고를 수 없다. 안정적 식별자로 라우팅한다. "키마다 AAD 하나" 규칙은 샤드 경계를 넘어 적용되며,
  결정적 암호문을 샤드 간 비교하려면 키·평문·AAD 가 모두 같아야 한다. 샤딩 미들웨어의 UDF 전달·charset
  보존 여부는 그 조합으로 별도 검증한다

- (개정 A8) 동일 키를 쓰는 모든 서버·컬럼·애플리케이션의 사용량을 합산하고,
  배포 전 키당 사용 예산·교체 기준을 보안 검토한다. component 는 사용량 계수·자동 교체를 하지 않는다.
- (개정 A8) 봉투 복사/복원은 새 암호화가 아니다. 재암호화·결정적 재시도의 조건을 구분하고,
  DB 복원으로 누적 사용량을 되돌리지 않는다. 사용 이력·난수 상태 안전성이 불확실하면 쓰기를 중단하고,
  모든 쓰기 주체의 난수 상태를 복구·확인한 뒤 안전하게 생성한 새 키로 재개한다.
- (개정 A8) 키 교체는 결정적 암호문의 JOIN/UNIQUE 이관과 과거 데이터·백업용 키 보존을 동반한다.
  가드 훅·벡터·샘플 충돌 테스트는 운영 중 nonce 재사용 탐지나 안전성 증명을 제공하지 않는다.

## 7. 라이선스 — GPLv2 (확정)

**결론: GPLv2 로 확정한다** (2026-09-28). `LICENSE` 에 GPLv2 전문을 두고, 소스에는
`SPDX-License-Identifier: GPL-2.0-only` 를 표기한다.

근거: MySQL 서버는 GPLv2(FOSS exception)이고 component 는 서버 헤더에 링크한다. 파생물
판단 시 GPLv2 배포가 안전한 선택이다. Apache/MIT 로 내리는 길은 검토 대상이었으나
채택하지 않았다. OpenSSL 3 는 Apache-2.0 이고 GPLv2 와의 조합은 MySQL 자신의 FOSS
exception 이 다루는 구성과 같다 — 우리는 서버가 이미 로드한 libcrypto 를 쓰고 별도
번들·정적 링크를 하지 않으므로(crypto-safety) MySQL 배포와 같은 형태다.
`GPL-2.0-only` 이며 "or later" 가 아니다: MySQL 이 GPLv2-only 이므로 상향 호환을
주장하지 않는다.

## 8. 확인된 사실 / 미확인

### 확인됨

| 항목 | 근거 |
|---|---|
| MySQL 8.4.11 · 9.4.0 이 GCM/GCM-SIV/SIV/CTR/XTS 거부 | 컨테이너 실측 |
| 8.0 → 9.7 문서의 모드 목록 불변 | dev.mysql.com 레퍼런스 |
| MariaDB 도 ECB/CBC/CTR 뿐 | MariaDB 문서 |
| component 가 UDF 등록 가능 | mysql_service_udf_registration (WL#8020) |
| component 가 keyring 에서 키 조회 가능 | keyring_reader_with_status |
| UDF 반환값 charset 지정 가능 (8.0.19+) | mysql_udf_metadata (WL#12370) |
| AES_ENCRYPT 는 8.0.30+ 에서 KDF(hkdf/pbkdf2_hmac) 지원 | 8.0 레퍼런스 — 참고용 |
| `udf_registration` · `mysql_udf_metadata` · `component_sys_variable_register`/`_unregister` · `mysql_runtime_error` · `mysql_current_thread_reader` 는 8.0.43 · 8.4.11 · 9.4.0 전부에 있다 | 세 태그의 `include/mysql/components/services/` 실측 |
| **component sysvar 의 SESSION 스코프와 `mysql_system_variable_reader` 는 9.0.0+ 전용** | 개정 A5 — 세 태그의 `component_sys_var_service.cc` · `mysql_system_variable.h` 실측 |
| `CONFIGURE_COMPONENTS()` 가 `components/*` 를 glob 하므로 `components/gcm` 에 넣고 재-configure 하면 in-tree 빌드된다 | `cmake/component.cmake` |
| RHEL9 계열에서 서버 소스가 요구하는 컴파일러는 8.0/8.4 = gcc-toolset-12, **9.x = gcc-toolset-14** | 각 태그 `CMakeLists.txt` 의 `ALTERNATIVE_PATHS`(`LINUX_RHEL9` 분기). 실측: toolset-13 으로는 9.4.0 configure 가 "Could not find devtoolset compiler/linker" 로 실패한다. `docker/versions.json` 의 `rhel9_toolset` 이 이 값의 원본 |
| 8.0 은 외부 boost(1.77) 필요, 8.4·9.x 는 `extra/boost` 로 번들 | 각 태그 `cmake/boost.cmake` |
| **한글 부분일치가 native LIKE 로 동작한다** — `gcm_decrypt(gcm_encrypt_det('홍길동',@k),@k) LIKE '%길%'` = 1, `CHARSET()` = `utf8mb4`, 전방·후방일치와 `LIKE '%kim%'`(대소문자 무시)도 1 | Phase S 실측 8.0.43 · 8.4.11 · 9.4.0 (`scripts/verify.sql`, `tests/integration/20_korean_like.sql`) → **decrypt_like 는 불필요** |
| `gcm_decrypt` + `ORDER BY` + `GROUP BY` 조합에서 `Created_tmp_disk_tables` 증가량 0 | Phase S 실측 8.0.43 · 8.4.11 · 9.4.0 (`build/<ver>/tmp_disk.txt`). 소규모 관측이고 대용량에서는 아직 재확인하지 않았다. `tests/load` 가 같은 카운터를 `created_tmp_disk_tables_delta` 로 보고하지만 이 ORDER BY + GROUP BY 가 아니라 자기 쿼리(`gcm_decrypt(col,@k) LIKE`) 기준이므로 이 행을 확인해주지는 않는다 |
| `EVP_CIPHER_fetch("AES-256-GCM")` · `EVP_MAC_fetch("HMAC")` 가 세 버전 모두에서 성공 | `INSTALL COMPONENT` 성공 자체가 증거 (init 에서 fetch 실패 시 설치가 실패한다) |
| 결정적 봉투가 `spec/envelope.md` §5.1 · §5.2 와 바이트 단위로 일치 | Phase S 실측 세 버전 (`tests/integration/11_roundtrip_det.sql`, `40_null_and_edge.sql`) |
| 32 바이트 아닌 키는 호출마다 거부된다 (0·5·31·33·64) | `tests/unit`, `tests/integration/00_install_and_signature.sql` |
| **계산된 문자열 식을 인자로 넘기면 8.0·8.4 가 값을 손상시킨다** | 개정 A7 — 세 버전 실측 (`tests/integration/91_server_udf_arg_defect.sql`) |
| MTR 스위트 `mysql-test/suite/gcm` 가 8.4.11 서버 트리에서 통과하고 `.result` 는 `--record` 산출물 | `scripts/mtr.sh 8.4` 실측. 복제 케이스는 8.4+ 경로인 `include/rpl/*` 를 쓴다 |
| ROW binlog 에서 primary·replica 의 암호문 바이트가 동일하고, STATEMENT 에서는 무작위 변형이 **갈라진다** | `gcm_replication.test` 실측 — 서버가 SBR 을 unsafe 로 경고하고 replica 가 함수를 재실행해 다른 nonce 를 만든다 |
| `INSTALL COMPONENT` 는 복제되지 않는다 | 같은 테스트 — replica 에서 UNINSTALL 후 복제된 행을 읽으면 `ER_SP_DOES_NOT_EXIST` |
| 독립된 두 서버(샤드)가 같은 키·평문·AAD 에 대해 같은 결정적 봉투를 만들고, AAD 가 다르면 달라진다 | `tests/e2e/scenarios/cross_shard_determinism.py` 실측 (8.4) |
| v1 봉투의 평문이 utf8mb4 가 아니면 결과가 불정 문자열이 되어 `LIKE` 가 조용히 0 을 낸다 | 8.4 실측 (latin1 `Müller` → `4DFC6C6C6572`, `LIKE '%ller%'` = 0). `spec/envelope.md` §2.3 에 MUST 로 기록 |
| `gcm_encrypt_det` 가 `const_item` 을 선언하면 상수 조회가 UNIQUE 인덱스를 탄다 (`type=const`) | `gcm_envelope.test` 실측. PREPARE 를 다른 파라미터로 재실행해도 값이 캐시되지 않는다 |
| 바이너리(비 UTF-8) 평문은 `utf8mb4` 요청에도 바이트가 보존된다 | `gcm_null_and_edge.test` 실측 — `binary` → `utf8mb4` 변환은 바이트를 복사한다 |
| **`args->lengths[i]` 는 변환 *전* 길이다** — 평문 인자를 utf8mb4 로 요청하므로 서버가 넓힌 뒤 component 에 넘긴다. latin1 `VARCHAR(1)` 의 `é` 는 lengths[0]=1 이지만 봉투는 31바이트 | 8.4·9.4 실측: 결과를 구체화하면 엄격 모드에서 `ER_DATA_TOO_LONG`, 비엄격 모드에서는 **30바이트로 잘려 저장되고 복호화가 실패**한다(경고 1265 뿐). 모든 charset 이 문자당 1바이트 이상이므로 `lengths[0]` 이 문자 수의 상한이고 utf8mb4 는 문자당 4바이트 이하 → `4 × lengths[0] + 29` 로 선언한다. `gcm_null_and_edge` 가 두 모드 모두 고정 |
| `initid->max_length` 는 서버가 `min<uint32>(...)` 로 좁히므로 **uint32 로 먼저 잘린다** | `sql/item_func.cc` 의 `udf_handler::fix_fields`. LONGTEXT 인자(4294967295)에 29 를 더하면 28 로 접혀 봉투가 최소 길이 아래로 잘린다 — 8.4 실측 `ERROR 1406 Data too long`. `udf_glue.h` 의 `envelope_max_length()` 가 포화 연산으로 막고 `gcm_null_and_edge.test` 가 고정한다 |
| component 는 `mysql_com.h` 를 include 할 수 없다 | 그 뒤의 `my_io.h` 가 `#error This header shall not be included in components` 를 낸다. 9.4.0 빌드에서 실패로 드러났고 8.0·8.4 는 조용히 통과했다 — 세 버전 빌드를 모두 돌려야 잡힌다 |
| `component_sys_variable_register::register_variable` 은 `*_CHECK_ARG` 의 `def_val` 을 **복사**한다 | `sql/server_component/component_sys_var_service.cc`: `sysvar_bool->def_val = bool_arg->def_val` (my_malloc 한 구조체로). 따라서 스택 지역 check-arg 전달이 안전하다 |
| **작은 복호화의 대부분은 암호가 아니라 호출별 EVP 컨텍스트 준비**이고, 스캔과 `gcm_decrypt` 를 함께 부르는 스캔 사이의 p95 차이는 `gcm_decrypt(col) LIKE` 질의의 73~85% 다(질의 간 차이이지 구성 요소 시간이 아니다) | 개정 A11 — 개발자 장비 프로토타입: 컨텍스트를 재사용한 16바이트 `open` 353 → 170 ns; 9.4 에서 100k 행 p95 49.6 → 23.2 ms(세션 1), 126.4 → 27.2 ms(세션 8); `tests/load` 의 평문 컬럼 기준선. CI 수치는 `docs/perf.md` 에 뒤따른다 |

### 미확인 (Phase S 에서 답한다)

- ~~charset 태깅으로 한글 LIKE 가 native collation 대로 동작하는지~~ → **확인됨** (위 표). decrypt_like 는 만들지 않는다
- ~~gcm_decrypt 가 디스크 temp 테이블에 평문을 남기는지~~ → 소규모에서는 증가량 0 (위 표). 대용량은 `tests/load` 의
  `created_tmp_disk_tables_delta` 로 계속 관측한다
- 운영 MySQL 이 자체 운영인지 (ECR 이미지 정황상 그렇게 보이나 미확정)
- ~~외부 keyring(Vault/KMS)을 운영에 둘 수 있는지~~ → 개정 A1 로 **범위 밖**
- 부하 기준선: `gcm_decrypt` + LIKE 의 p95 가 `AES_DECRYPT` 대비 1.2배 이내인지 (10k/100k/300k, 동시 1/8/32).
  0.1.0 에서 CI 러너(ubuntu-24.04, 8.4.11, 300k 행, 세션당 40 표본) 3회 측정으로 확정: 비율 0.80~0.95, 직렬 p95 235~255ms.
  게이트는 약속(1.2배)이 아니라 측정값에서 유도한 1.10배로 강제한다 — 근거와 표는 `docs/perf.md`.
  `tests/load/run.py --gate` 가 게이트이고 결과는 `docs/perf.md` 에 누적한다
- ~~부하 baseline — 릴리스 빌드 + 알려진 하드웨어에서의 수치~~ → **확인됨**: CI 러너에서 3회 측정하고
  `tests/load/baseline.json` 의 게이트를 그 값에서 유도했다 (`docs/perf.md` "Release baseline — 0.1.0")
- ~~행당 비용이 어디서 나는지~~ → **확인됨** (`tests/bench`, `docs/perf.md`): 복호화 경로는 맨 EVP 대비
  오버헤드가 측정되지 않고(0.97~1.03), 봉투·오류 변환·버퍼 관리·소거를 합친 구조적 비용은 세 암호화 경로
  모두 10% 미만이다. 결정적 변형이 평범한 봉인의 3.5~5배인 것은 HMAC 2회 때문이며 구현 오버헤드가 아니다.
- ~~`derive_nonce_key` 는 키에만 의존하는데 `encrypt_det` 가 호출마다 다시 계산한다 (작은 평문에서
  `seal_det` 의 약 40%). `UDF_INIT` 당 캐시하면 의미 있는 절감이지만, 키가 행별 인자이므로 캐시 유효성 판단에
  **키 복사본을 행 사이에 보관**해야 한다 — `crypto-safety.md` 의 키 취급과 정면으로 맞선다. 성능을 위해
  이걸 하려면 개정으로 올려 보안 검토를 받는다.~~ → **개정 A11 로 결정**: `UDF_INIT` 은 유도된 nonce 키 곁에,
  그리고 `gcm_decrypt` 의 스케줄된 EVP 컨텍스트 곁에 키 복사본을 둘 수 있다 — 거기 적은 불변 조건(상수 시간
  비교, 교체 전 소거, 모든 오류에서 잊기, deinit 에서 소거, 공유 금지) 아래서. 프로토타입 측정값은 A11 에,
  CI 수치는 `docs/perf.md` 에 둔다. A11 이 요청하는 보안 검토는 아직 남아 있다.

## 9. 참고

- MySQL: Keyring component services
- WL#4102 Service registry and component infrastructure
- WL#8020 Add a UDF registration service
- WL#12370 Extend the UDF API to handle character sets
- WL#6781 Support multiple AES Encryption modes
- Extending MySQL: Adding a Loadable Function
- Keyring Component Installation
