# tests/ — unit · integration · probe · e2e · load

- `.agents/rules/architecture.md` — testing the core without a server, internal test entry points and
  the SQL boundary
- `.agents/rules/testing.md` — **GWT is mandatory**, the pyramid, vectors in one place, keeping the
  Korean `LIKE` cases, the load gate
- `.agents/rules/stack-cpp.md` (unit), `.agents/rules/stack-python.md` (e2e/load)

`tests/probe/` is a test-only component (issue #43) that registers throwaway UDFs to pin a server
defect. Its name is reserved and `scripts/check-architecture.py` refuses it anywhere under `src/` or
`docker/`, so it cannot reach the component build or an image.

Skills: `unit-tests`, `integration-tests`, `e2e-load-tests`, `dev-container`.
