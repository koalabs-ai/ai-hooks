#!/usr/bin/env bash
# Fill the publish-time placeholders in the site, README, packaging and plugin files.
# usage: scripts/set-site-url.sh <site-base-url> <github-owner>      e.g. https://example.org/ai-hooks acme
set -euo pipefail
BASE="${1:?site base url, no trailing slash}"; OWNER="${2:?github owner or org}"
cd "$(dirname "$0")/.."
sed -i "s#https://REPLACE-BASE-URL#$BASE#g; s#github.com/OWNER/#github.com/$OWNER/#g; s#OWNER/ai-hooks#$OWNER/ai-hooks#g; s#^BASE = .*#BASE = \"$BASE\"#; s#^REPO = .*#REPO = \"https://github.com/$OWNER/ai-hooks\"#" site/build.py
python3 site/build.py
grep -rl "OWNER\|REPLACE-BASE-URL" --include='*' . 2>/dev/null | grep -v '^./.git/' | grep -v 'dist/' | grep -v '^./scripts/' | while read -r f; do
  sed -i "s#github.com/OWNER/#github.com/$OWNER/#g; s#OWNER/ai-hooks#$OWNER/ai-hooks#g; s#OWNER/homebrew-tap#$OWNER/homebrew-tap#g; s#https://REPLACE-BASE-URL#$BASE#g" "$f"
done
echo "placeholders left:"; grep -rn "OWNER\|REPLACE-BASE-URL\|PLACEHOLDER" . --exclude-dir=.git --exclude-dir=dist | cut -c1-140 || true
