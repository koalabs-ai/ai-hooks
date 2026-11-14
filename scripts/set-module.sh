#!/usr/bin/env bash
# Rewrite the Go module path (the import path `go install` and pkg.go.dev use).
# usage: scripts/set-module.sh github.com/<org>/ai-hooks
set -euo pipefail
NEW="$1"
cd "$(dirname "$0")/.."
OLD="$(awk '/^module /{print $2}' go.mod)"
[ "$OLD" = "$NEW" ] && exit 0
grep -rl --include='*.go' --include='go.mod' --include='*.yaml' --include='*.md' "\"$OLD\|$OLD/\|^module $OLD" . 2>/dev/null | while read -r f; do
  sed -i "s#\"$OLD/#\"$NEW/#g; s#^module $OLD\$#module $NEW#" "$f"
done
go build ./... && echo "module is now $NEW"
