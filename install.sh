#!/bin/sh
# Install the latest ai-hooks release for this machine, verifying its sha256.
#   curl -fsSL https://raw.githubusercontent.com/koalabs-ai/ai-hooks/main/install.sh | sh
# Options (environment): AI_HOOKS_VERSION (default: latest), AI_HOOKS_PREFIX (default: ~/.local/bin),
#                        AI_HOOKS_REPO (default: koalabs-ai/ai-hooks), AI_HOOKS_BASE_URL (override, for tests)
set -eu
# AI_HOOKS_SHA256: pin the archive's expected sha256 yourself (then the checksums file is not trusted at all)
REPO="${AI_HOOKS_REPO:-koalabs-ai/ai-hooks}"
case "$REPO" in *[!A-Za-z0-9._/-]*|/*|*/|*//*) echo "bad AI_HOOKS_REPO" >&2; exit 1 ;; esac
PREFIX="${AI_HOOKS_PREFIX:-$HOME/.local/bin}"
case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;; esac
if [ -n "${AI_HOOKS_BASE_URL:-}" ]; then
  base="$AI_HOOKS_BASE_URL"; ver="${AI_HOOKS_VERSION:?set AI_HOOKS_VERSION with AI_HOOKS_BASE_URL}"
else
  ver="${AI_HOOKS_VERSION:-}"
  if [ -z "$ver" ]; then
    ver="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n1)"
  fi
  [ -n "$ver" ] || { echo "could not find the latest version" >&2; exit 1; }
  base="https://github.com/$REPO/releases/download/v$ver"
fi
case "$ver" in ""|*[!A-Za-z0-9._-]*) echo "bad version" >&2; exit 1 ;; esac
name="ai-hooks_${ver}_${os}_${arch}.tar.gz"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$base/$name" -o "$tmp/$name"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"
want="${AI_HOOKS_SHA256:-$(awk -v n="$name" '$2 == n {print $1}' "$tmp/checksums.txt")}"
[ -n "$want" ] || { echo "no checksum listed for $name" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$tmp/$name" | awk '{print $1}')"; else got="$(shasum -a 256 "$tmp/$name" | awk '{print $1}')"; fi
[ "$got" = "$want" ] || { echo "checksum mismatch for $name" >&2; exit 1; }
tar -xzf "$tmp/$name" -C "$tmp" ai-hooks
mkdir -p "$PREFIX"
install -m 0755 "$tmp/ai-hooks" "$PREFIX/ai-hooks"
echo "installed $PREFIX/ai-hooks ($("$PREFIX/ai-hooks" version))"
case ":$PATH:" in *":$PREFIX:"*) ;; *) echo "note: $PREFIX is not on your PATH" >&2 ;; esac
