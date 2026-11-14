#!/usr/bin/env bash
# Build release archives (linux/darwin/windows x amd64/arm64), checksums.txt and a CycloneDX SBOM into dist/release.
# Archives are reproducible: fixed timestamps and ownership, gzip without a name, -trimpath, CGO off.
# usage: scripts/release.sh 0.1.0
set -euo pipefail
VERSION="${1:?version without the v, e.g. 0.1.0}"
cd "$(dirname "$0")/.."
OUT=dist/release
rm -rf "$OUT" dist/stage
mkdir -p "$OUT" dist/stage
export CGO_ENABLED=0
for os in linux darwin windows; do
  for arch in amd64 arm64; do
    exe=ai-hooks; [ "$os" = windows ] && exe=ai-hooks.exe
    d="dist/stage/${os}_${arch}"
    mkdir -p "$d"
    GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$d/$exe" ./cmd/ai-hooks
    cp LICENSE NOTICE README.md "$d/"
    name="ai-hooks_${VERSION}_${os}_${arch}"
    if [ "$os" = windows ]; then
      python3 -I - "$d" "$OUT/${name}.zip" "$exe" <<'PYZ'
import sys, zipfile
d, out, exe = sys.argv[1:4]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for n in (exe, "LICENSE", "NOTICE", "README.md"):
        zi = zipfile.ZipInfo(n, date_time=(1980, 1, 1, 0, 0, 0))
        zi.external_attr = 0o755 << 16 if n == exe else 0o644 << 16
        zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, open(f"{d}/{n}", "rb").read())
PYZ
    else
      tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$d" -cf - "$exe" LICENSE NOTICE README.md | gzip -n -9 > "$OUT/${name}.tar.gz"
    fi
  done
done
( cd "$OUT" && sha256sum ./*.tar.gz ./*.zip | sed 's#\./##' > checksums.txt )
GOV="$(go env GOVERSION)"
python3 -I - "$VERSION" "$GOV" > "$OUT/ai-hooks_${VERSION}_sbom.cdx.json" <<'PY'
import json, sys
v, gov = sys.argv[1], sys.argv[2]
print(json.dumps({
  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
  "metadata": {"component": {"type": "application", "name": "ai-hooks", "version": v, "licenses": [{"license": {"id": "Apache-2.0"}}]}},
  "components": [{"type": "library", "name": "go-standard-library", "version": gov, "description": "ai-hooks has no dependencies outside the Go standard library"}],
}, indent=2))
PY
rm -rf dist/stage
ls -l "$OUT"
