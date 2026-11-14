# Parity with the original shape detectors

The first 36 detectors of `ai-hooks redact` are a Go port of a Python implementation (`re`-based) that had been in daily use. Go's RE2 has no lookaround, so every lookbehind and lookahead was rebuilt as an explicit check (see the comment at the top of `internal/redact/redact.go`). The claim is "byte-identical output **in compatibility mode**", and it was checked, not assumed.

## Compatibility mode

`AI_HOOKS_PARITY=1` switches off everything added after the port: the extra detectors, input normalisation (ANSI, zero-width characters, escapes), the keyed fingerprints and the public detector names. What is left is the original detector set, with the original names and plain `sha256` fingerprints. The default mode is a superset: it finds more, names things clearly and uses keyed fingerprints. The old names are accepted by `ai-hooks explain` and mapped in [`DETECTORS.md`](DETECTORS.md).

## What was run (2026-11-13)

The original's own parity checker, pointed at this binary with `AI_HOOKS_PARITY=1`:

| check | result |
|---|---|
| synthetic texts built to hit every edge (lookbehinds after `\n` escapes, Unicode letters/digits/spaces next to tokens, `sk-ant-` vs `sk-`, CRLF, the known-hashes layer) | 20,000/20,000 identical |
| real text files (10,155 Markdown, Python and prompt files), compared by sha256 of the output | 10,155/10,155 identical |
| command-line behaviour (stdin newline handling, empty input, exit code) | 6/6 identical |

The long run spanned a few rebuilds of the binary, so it was repeated on the final build: 4,000/4,000 synthetic texts and 6/6 command-line cases identical. Known differences that exist by design, both outside anything a real secret looks like: invalid UTF-8 input is kept and redacted (the Python raises and prints nothing), and inside case-insensitive patterns `İ` and `ı` do not fold to `i` as they do in Python.

## One intended difference in default mode

`twilio-auth-token` (formerly `twilio-auth-hex`: a bare 32-hex value followed by a delimiter) used to redact every 32-hex value, including systemd invocation ids, md5 sums and trace ids. It now skips a value when the same line, just before it, names one of: invocation, machine id, boot id, md5, checksum, etag, digest, hash, sha, integrity, trace, span, request id, container id, commit, uuid, build id. A bare 32-hex value with no such word is still redacted. This is also a limit: text on the same line can suppress this one detector. Compatibility mode does not have the exemption.

Not fixable without losing real detections: `md5sum` output (`<32 hex>  filename`) has no label, so it is still redacted. It is listed as a known false alarm in the corpus.

## The guard

The guard is a port of two shell/Python guards, extended since. It was compared with them on a sample of 2,000 distinct shell commands taken from real agent sessions: 1,996 decisions agree. Of the 4 differences, 3 are commands the new rules block that the originals allowed (new coverage: an inline interpreter naming a secret file, `/proc/*/environ`, a file glob), and 1 is a command the originals blocked and the new guard allowed (a `grep` over `*.env` files; fixed afterwards and covered by a test). Nothing else the originals blocked is allowed here: 39 commands blocked by the originals are blocked by ai-hooks too. Messages differ on purpose (English, no site-specific paths), and the override comments differ (`# ai-hooks: ok`).

## Re-running

```sh
AI_HOOKS_PARITY=1 ai-hooks --redact-check < cases.jsonl   # one JSON string per line in, redacted JSON string out
ai-hooks --guard-check < commands.jsonl                   # one JSON command per line in, "allow" or "block<TAB>rule" out
```
