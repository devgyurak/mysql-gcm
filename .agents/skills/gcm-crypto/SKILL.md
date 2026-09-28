---
name: gcm-crypto
description: OpenSSL 3 EVP 로 AES-256-GCM 봉투·결정적 nonce·키 소거를 구현하는 절차와 참조 코드. gcm.cc / envelope.cc / nonce.cc 및 내부 벡터 생성 도구를 작성·수정할 때 사용. 완료 후 crypto-reviewer 를 돌린다.
---

# gcm-crypto

먼저 `.agents/rules/crypto-safety.md` 를 읽는다. 이 스킬은 그 규칙을 코드로 옮기는 방법이다.

## 봉투 (spec/envelope.md 가 확정본; 없으면 AGENTS.md §2 제안값)
```
random : 0x02 || nonce(12) || ct(len(pt)) || tag(16)      min len = 29
det    : 0x03 || nonce(12) || ct(len(pt)) || tag(16)      min len = 29  (개정 A2 확정 — nonce 저장)
```
`envelope.h`: `constexpr unsigned char kVerRandom = 0x02, kVerDet = 0x03; constexpr size_t kNonceLen = 12, kTagLen = 16, kKeyLen = 32;`
`envelope.cc` 는 파싱만 한다 (version 확인, 오프셋 계산, 길이 검증). 암호 호출 없음 → 단위 테스트가 가장 촘촘한 곳.

## 결정적 nonce — `nonce.cc`
```
nonce_key = HMAC-SHA256(key, "mysql-gcm/v1/det-nonce")      # 도메인 분리, 레이블은 상수 kDetNonceLabel
nonce     = HMAC-SHA256(nonce_key, plaintext)[:12]
```
```cpp
// EVP_MAC 사용 — HMAC() 레거시 금지
static EVP_MAC *g_hmac;  // crypto_init 에서 EVP_MAC_fetch(nullptr, "HMAC", nullptr)
bool hmac_sha256(const uint8_t *k, size_t kl, const uint8_t *m, size_t ml, uint8_t out[32]) {
  OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0), OSSL_PARAM_construct_end() };
  EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(g_hmac); if (!ctx) return false;
  size_t outl = 0;
  bool ok = EVP_MAC_init(ctx, k, kl, params) && EVP_MAC_update(ctx, m, ml) && EVP_MAC_final(ctx, out, &outl, 32) && outl == 32;
  EVP_MAC_CTX_free(ctx); return ok;
}
```
`nonce_key` 32B 는 스택 버퍼, 사용 후 `OPENSSL_cleanse`.

## GCM — `gcm.cc`
```cpp
static EVP_CIPHER *g_aes_gcm;   // crypto_init: EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr); nullptr 면 init 실패
Error seal(const uint8_t key[32], const uint8_t nonce[12], span pt, span aad, uint8_t *ct, uint8_t tag[16]) {
  CtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free); int len = 0;
  if (!ctx || !EVP_EncryptInit_ex2(ctx.get(), g_aes_gcm, nullptr, nullptr, nullptr)) return Error::openssl;
  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr)) return Error::openssl;
  if (!EVP_EncryptInit_ex2(ctx.get(), nullptr, key, nonce, nullptr)) return Error::openssl;
  if (aad.size && !EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data, (int)aad.size)) return Error::openssl;
  if (pt.size && !EVP_EncryptUpdate(ctx.get(), ct, &len, pt.data, (int)pt.size)) return Error::openssl;
  if (!EVP_EncryptFinal_ex(ctx.get(), ct + len, &len)) return Error::openssl;
  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, tag)) return Error::openssl;
  return Error::ok;
}
Error open(const uint8_t key[32], const uint8_t nonce[12], span ct, span aad, const uint8_t tag[16], uint8_t *pt) {
  // ... DecryptInit_ex2, SET_IVLEN, key/nonce, AAD, DecryptUpdate ...
  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag))) return Error::openssl;
  if (EVP_DecryptFinal_ex(ctx.get(), pt + len, &len) <= 0) { OPENSSL_cleanse(pt, ct.size); return Error::bad_tag; }  // 미인증 평문 폐기
  return Error::ok;
}
```
- 무작위: `RAND_bytes(nonce, 12) == 1` 아니면 `Error::rng`.
- 오류 enum: `ok, bad_envelope, bad_tag, bad_key_len, rng, openssl`. 문자열 오류 금지.
- `crypto_init`/`crypto_deinit` 는 fetch 핸들만 관리. 컨텍스트는 호출마다.

## 반드시 붙이는 테스트 (unit-tests 스킬, GWT)
NIST CAVP `gcmEncryptExtIV256.rsp` / `gcmDecrypt256.rsp` 중 IV 96·tag 128 케이스를 `spec/test-vectors.json` 에 변환해 전부 통과. 태그·nonce 1비트 변조, 잘린 봉투, 키 길이, det 왕복·동등성, nonce_key 유도 벡터(수기로 Python `cryptography` 로 생성해 교차 확인).

## 완료 조건
- [ ] `rg -n --type cpp -e 'EVP_aes_' -e '\bHMAC\(' -e '\b(s?rand)\(' -e 'std::string\s+\w*key' src` 가 종료 코드 1 (일치 없음). 0 이면 위반, 2 면 검색 실패
- [ ] ASan/UBSan 단위 테스트 통과
- [ ] `crypto-reviewer` 서브에이전트 P1 0
