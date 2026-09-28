#!/usr/bin/env bash
# PreToolUse(Bash) guard. Exit 2 blocks the tool call (message on stderr); exit 0 allows.
# Blocks: force-push, staging/committing key material, enabling general_log/log_raw.
# Logic lives in guard.py so the hook JSON on stdin is not shadowed by a heredoc.
set -euo pipefail
exec python3 "$(dirname "$0")/guard.py"
