---
paths:
  - "scripts/**/*.py"
  - "tests/e2e/**/*.py"
  - "tests/load/**/*.py"
  - "**/*.py"
---
<!-- Generated from .agents/rules/stack-python.md by scripts/agents-sync.py — edit the source. -->
# Python conventions

- 3.10+, with as few dependencies as possible. Python is used only for internal development tools and
  SQL test runners. Do not build a shippable encryption package in it.
- The vector generator depends on `cryptography`, from `scripts/requirements.txt`. The SQL E2E and load
  runners standardise on `PyMySQL` and do their encryption and decryption through the server's SQL
  functions.
- `ruff` (lint + format) and `mypy --strict`, both enforced in CI. A `# type: ignore` needs a comment
  giving the reason.
- Do not expose a public encrypt/decrypt/parse API. Keep the minimum crypto construction the vector
  generator needs inside the script, built on `cryptography`'s primitives.
- `scripts/gen-vectors.py --check` verifies that the output is reproducible. Envelope errors, tag
  failures and round trips are verified by the C++ unit tests and the SQL integration tests.
- Load and E2E scripts: `argparse`, results as JSON on stdout, the human-readable summary on stderr.
  A threshold comparison is reported through the exit code, which is what makes it a CI gate.
- Database connection details come from environment variables (`MYSQL_HOST` and friends) only. No
  password in code or in a configuration file.
