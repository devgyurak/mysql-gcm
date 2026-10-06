# src/ — component sources

These rules apply to this directory on top of the root `AGENTS.md`. Read them before starting.
- `.agents/rules/architecture.md` — module responsibilities, dependency direction, state lifetimes,
  server compatibility, test boundaries
- `.agents/rules/component-src.md` — component services, charset tagging, the registration API
- `.agents/rules/crypto-safety.md` — fetching EVP algorithms by name, the 32-byte key, cleansing,
  strict semantics
- `.agents/rules/stack-cpp.md` — C++17, RAII, error enums, clang-tidy

Skills: `.agents/skills/mysql-component`, `gcm-crypto`, `sysvar-config`. When an API is uncertain,
confirm it against the headers with the `component-api-researcher` role prompt (`.claude/agents/`).
