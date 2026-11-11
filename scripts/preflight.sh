#!/usr/bin/env bash
# Refuse to push a repository that contains a credential.
#
# Run automatically as a pre-push hook:
#   ln -sf ../../scripts/preflight.sh .git/hooks/pre-push
#
# A token pasted into an issue, a README or a transcript is compromised the moment it is
# written. This catches the accidental commit before it becomes a public one.

set -uo pipefail

patterns=(
  'ghp_[A-Za-z0-9]{30,}'
  'github_pat_[A-Za-z0-9_]{40,}'
  'sk-[A-Za-z0-9_-]{20,}'
  'AKIA[0-9A-Z]{16}'
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
  'xox[baprs]-[A-Za-z0-9-]{10,}'
)

# bash 3.2 ships on macOS without mapfile, so stay with plain read loops.
staged=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)
if [ -z "$staged" ]; then
  echo "preflight: nothing staged, skipping"
  exit 0
fi

failed=0
count=0
while IFS= read -r file; do
  [ -n "$file" ] || continue
  [ -f "$file" ] || continue
  count=$((count + 1))
  for pattern in "${patterns[@]}"; do
    if grep -anE -- "$pattern" "$file" >/dev/null 2>&1; then
      line=$(grep -anE -- "$pattern" "$file" | head -1 | cut -d: -f1)
      echo "preflight: SECRET in $file:$line  (pattern: ${pattern:0:12}…)"
      failed=1
    fi
  done
done <<< "$staged"

if [ "$failed" -ne 0 ]; then
  cat >&2 <<'MSG'

Refusing to continue: a credential is staged.

  1. Revoke it at the provider. Deleting the commit is not enough — the value existed
     on disk and in your shell history, so treat it as burned.
  2. Remove it from the working tree and re-stage.
  3. If it is already in history, rewrite history before pushing, then rotate again.

MSG
  exit 1
fi

echo "preflight: clean ($count files)"
