# 암호 안전 규칙 (항상 적용)

이 프로젝트의 전부는 "MySQL 서버 안에서 AEAD 를 안전하게 한다" 이다. 아래는 협상 대상이 아니다.

## OpenSSL
- 알고리즘은 이름으로 가져온다: `EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL)`, `EVP_MAC_fetch(NULL, "HMAC", NULL)` + digest `SHA256`.
  `EVP_aes_256_gcm()`, `HMAC()` 같은 레거시 심볼 직접 호출 금지 — 빌드 시점 OpenSSL 에 묶이고 provider 를 우회한다.
- fetch 결과는 component init 에서 한 번 만들어 캐시하고 deinit 에서 `EVP_CIPHER_free` / `EVP_MAC_free`. UDF 호출마다 fetch 하지 않는다.
- 서버 프로세스가 이미 로드한 libcrypto 를 쓴다. OpenSSL 정적 링크·번들·다른 버전 dlopen 금지 (심볼 충돌로 서버가 죽는다).
- nonce 길이 12, tag 길이 16 고정. 다른 길이를 받는 인자를 만들지 않는다.
- 무작위 nonce 는 `RAND_bytes`. 반환값 1 아님은 에러. `rand()`·시간 기반 금지.
- 복호화는 `EVP_CTRL_AEAD_SET_TAG` 를 `EVP_DecryptFinal_ex` **이전**에 호출하고, Final 의 반환값이 태그 검증 결과다.
  Final 이 0 이면 출력 버퍼를 `OPENSSL_cleanse` 로 폐기한다 — 미인증 평문을 절대 반환하지 않는다.

## 키 취급 (개정 A1: 키는 SQL 인자)
- 키는 UDF 인자 `key` 로만 들어온다. **정확히 32 바이트**. 아니면 에러. 접기(XOR)·해시·패딩으로 길이를 맞추지 않는다 (`AES_ENCRYPT` 의 약점 미재현).
- 키·평문은 `UDF_ARGS` 가 준 버퍼를 직접 참조하고, 복사본을 만들었다면 사용 직후 `OPENSSL_cleanse`. `std::string` 에 담지 않는다 (재할당 시 복사본이 남는다).
- 결정적 nonce 키는 `HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")` 로 유도한다. 암호 키를 HMAC 키로 직접 쓰지 않는다 (도메인 분리). 레이블 문자열은 `nonce.h` 의 상수 하나.
- 키 바이트를 저장소 파일·my.cnf·sysvar·환경변수·테스트 픽스처에 두지 않는다. 예외는 `spec/test-vectors.json` 의 공개 벡터 키뿐.
- 키가 SQL 문에 등장해 서버 로그에 남을 수 있음은 **알려진 운영 제약**(design §6)이다. 코드로 우회하려 하지 않는다 (로그 필터링 코드 금지 — 서버 내부를 건드리는 범위 밖 작업).

## 실패 의미론
- 태그 불일치: `gcm.strict=ON`(기본) → 에러(`mysql_runtime_error` 서비스, 전용 메시지). OFF → NULL. 그 외 상태 없음.
- 잘못된 봉투(길이 부족·알 수 없는 version)·잘못된 키 길이: strict 와 무관하게 항상 에러. 데이터 손상·설정 오류는 설정으로 숨기지 않는다.
- 에러 메시지·서버 로그·assert·예외 문자열에 키·평문·nonce·태그·암호문 바이트를 넣지 않는다. 길이와 version 바이트까지만 허용.

## 결정적 변형
- `nonce = HMAC-SHA256(nonce_key, plaintext)[:12]`. AAD 는 nonce 계산에 넣지 않는다 (design §5.2). 바꾸려면 설계 문서 먼저.
- 결정적 변형은 조인·UNIQUE·정확일치 용도다. 자유 텍스트에 쓰지 말라는 경고를 문서·함수 주석에 유지한다.
- 동일 키를 쓰는 모든 결정적 호출은 서버·컬럼·애플리케이션에 관계없이 같은 AAD 바이트열(또는 항상 빈 값)을 사용한다. 다른 AAD 영역에는 다른 키를 쓴다. 암호문 JOIN 은 양쪽의 키·AAD 가 같아야 한다. 호출 간 AAD 정책을 component 가 검증한다고 설명하지 않는다.
- 동등성·빈도·길이 노출과 nonce 충돌 가정을 함께 설명한다. 벡터 통과·샘플 충돌 테스트·충돌 확률 계산을 구성 전체의 안전성 증명으로 표현하지 않는다.

## 운영 책임 (개정 A8)
- 배포 전 동일 키의 모든 사용처를 합산할 사용량 예산·키 교체 기준을 보안 검토한다. component 에 키별 계수·자동 교체·nonce 중복 탐지가 있다고 가정하지 않는다. 임의의 수치를 보편적인 안전 한도로 문서화하지 않는다.
- 봉투 복사/복원과 재암호화는 구분한다. 무작위 재암호화는 새 nonce, 결정적 재시도는 같은 키·평문·AAD 를 사용한다. 복구 시 누적 사용량을 되돌리지 않는다. 사용 이력이나 난수 상태의 안전성을 확인할 수 없으면 새 쓰기를 중단한다. 모든 쓰기 주체의 난수 상태를 복구·확인하고 독립적으로 안전하게 생성한 새 키로 재개한다. 키 교체만으로 중복 난수 상태가 해결되지는 않는다.
- 키 교체 시 결정적 암호문 JOIN/UNIQUE 이관과 과거 데이터·백업용 키 보존을 계획한다. 키 관리 자체는 외부 운영 책임이며 component 의 범위를 확장하지 않는다.
- 개발 가드 훅은 명령 차단 도구이며 운영 중 암호 호출 감시가 아니다. 자세한 운영 안내는 `docs/ops-constraints.md` 11–13항과 README 에 함께 유지한다.

## 코드 리뷰에서 자동 차단(P1)되는 패턴 (C++ `src/` 범위. 내부 벡터 생성 도구의 Python `hmac.HMAC` 는 허용 라이브러리이므로 해당 없음 — 언어별 검사는 code-review 스킬 3단계)
`EVP_aes_`, `HMAC(`, `rand(`, `srand(`, `printf.*key`, `LogErr.*(key|plain)`, `std::string key`, 하드코딩 키 리터럴,
키 길이 != 32 를 허용하는 분기, 태그 실패를 strict 검사 없이 NULL 로 만드는 분기, `EVP_DecryptFinal_ex` 반환값 미검사.
