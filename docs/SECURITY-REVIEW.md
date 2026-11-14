# Security review before the first release

Date: 2026-11-13. Scope: every package (`cmd/`, `internal/redact`, `internal/guard`, `internal/adapters`, `internal/mcp`, `internal/report`), `install.sh`, `action.yml`, the workflows, `Dockerfile`, the packaging files and the documentation claims. This is a summary; the raw reviewer output and the working notes are kept privately because some of the early findings describe bypasses that were not yet fixed when they were written.

## Method

1. **Two independent model reviews**, package by package, with the same checklist (command injection, unsafe file writes in `install`, regex complexity, redaction and guard bypasses, leakage by the tool itself, supply chain, MCP, claims stronger than the code): **GLM-5.3** (66 findings) and **MiniMax-M3** (90 findings, 5 rated high). Model output was treated as claims to verify, not as truth: every finding was reproduced, reasoned through, or dismissed.
2. **Static tools, run for real:** `go vet`, `staticcheck`, `gosec` (51 issues), `govulncheck`, `semgrep` with `--metrics=off` and the golang, secrets, GitHub Actions and Dockerfile rule packs (4 findings; rules were fetched, no code was uploaded anywhere), `actionlint`, `shellcheck`, `gitleaks` over the working tree and the full history.
3. **Adversarial tests written first** (`internal/redact/security_test.go`, `internal/guard/security_test.go`, adapters, MCP, end-to-end): ANSI colour codes, zero-width characters, CRLF, JSON and URL escapes, UTF-16 and BOM input, truncated and unterminated private keys, partial writes at every chunk size, very long lines, binary and hostile input, about 130 guard bypass and safe-form cases, pathological commands, comments that pretend a command is safe, override injection, symlinks and clobbering in `install`, process-group timeouts, and a run of the whole binary with networking disabled.

## Result

**No unfixed high-severity finding.** Everything below was fixed with a test, shown to be a false positive, or accepted and written down in [the security model](SECURITY-MODEL.md).

### Fixed (with a test)

| Finding | Source | Severity | Fix |
|---|---|---|---|
| A secret wrapped in ANSI colour codes, or containing zero-width characters, escapes, or UTF-16 encoding, was not matched | own tests | high | input is normalised before matching; UTF-16 and BOM inputs decoded |
| A private key whose END line never arrives (cut output, unterminated stream) was printed | own tests | high | such blocks are replaced with a marker; a truncated-key detector was added |
| A comment such as `# wc -l` or `# ai-hooks redact` made a risky command look safe | own tests, GLM | medium | shell comments are stripped before analysis |
| Mentioning `ai-hooks redact` anywhere in a command (even in a string) disabled the rules | GLM | medium | only a pipe stage or the `exec` wrapper counts |
| `# ai-hooks: ok` counted anywhere in the command | GLM, MiniMax | medium | override must be the last thing on the command; `AI_HOOKS_NO_OVERRIDE=1` disables overrides |
| Readers and shapes the guard missed (`xargs`, `$(<file)`, `cut`, `base64`, `dd`, inline interpreters naming a secret file, `.env*`, multi-suffix env files, `/usr/bin/env`, `declare -x`) | own tests | medium | rules and tests added |
| `exec` / `safe_run` waived the check on printing a secret variable, though redaction is by shape | GLM, own review | medium | `CheckExec` keeps those rules; a short-value `NAME=value` detector was added |
| `install` removed a user's own hooks sitting in the same group as ours | MiniMax | medium | only our entries are removed |
| The backup step could write through a symlink | MiniMax | medium | exclusive create |
| `uninstall` could delete a file that only mentioned ai-hooks, or a symlink's target | MiniMax, GLM | medium | strict markers; removes the path, not the target |
| `safe_run` timeout left child processes running and the call blocked | MiniMax, GLM | medium | process-group kill and wait delay |
| `--allow-run` prefix could carry a second command | MiniMax | medium | commands with shell metacharacters are refused when an allow list is set |
| One-entry lower-case cache keyed by an address could return another string's text | GLM, MiniMax | medium | the cache keeps its source alive |
| Guard engine kept per-call state without a lock | GLM | medium | serialised |
| Fingerprints were a plain truncated hash: weak secrets could be confirmed offline | brief, MiniMax | medium | keyed HMAC with a per-install key; key file permissions enforced |
| `install.sh`: unchecked version and repository strings, regex-matched checksum line | GLM, MiniMax | low | validated; exact match; `AI_HOOKS_SHA256` pin |
| Newlines in the binary path, TOML string escaping, label characters in the known-hash marker, PEM END test too loose | GLM, MiniMax | low | fixed |
| Dockerfile had no `USER` | semgrep | low | `USER 65532` |
| README and design note claims stronger than the code (stale detector count, sha256 fingerprint, absolute wording) | GLM, MiniMax | low | rewritten and qualified |
| 4 unused or style items | staticcheck | info | fixed |

### False positives

`gosec` G101 on the detector name and description tables, G115/G404 on the seeded pseudo-random generator that expands corpus templates (deterministic on purpose), `semgrep` `math/rand` on the same code and PGP-block rules on the detector and corpus templates, `shellcheck` SC2016, MiniMax's reading of input normalisation as a leak (the output is the normalised text, redacted; this is documented).

### Accepted, and stated in the security model or README

- Detection is by shape; encoded forms (base64, hex), keys split across lines, and a context word on the same line (`md5`, `trace`) that suppresses one detector can pass.
- A deliberately opaque command (aliases, computed `eval`, a script that prints a secret, a secret copied into an innocently named variable) is not understood by the guard.
- The guard fails open; a broken or missing binary does not block the agent. The opencode plugin and the other adapters behave the same way.
- Overrides, hook configuration and the rules file are writable by the agent's user: not a defence against a hostile agent.
- `gosec` G204/G304/G702/G703 on the command and path inputs of `exec`, `scan`, `install` and `safe_run`: they are the purpose of those commands and are documented; `gosec` G104 on best-effort writes to stdout.
- `install.sh` fetches the checksum file from the same release as the archive (pin it with `AI_HOOKS_SHA256`); the Docker base image is not pinned by digest; the AUR recipe is a template whose checksum is filled at release.
- Inline interpreters that only print environment variable names are blocked (a usability cost of a broad rule).

### Clean

`govulncheck`: no vulnerabilities. `actionlint`, `staticcheck`, `go vet`, `shellcheck`: clean. `gitleaks`: only the intentional fakes in `corpus/`, allow-listed. Dependencies outside the standard library: none. Workflows: every action pinned to a commit SHA. No network: the binary links no HTTP or TLS package, and its tests run it with networking disabled.

## Not reviewed

Third-party harnesses' hook implementations; a Windows run (the binary builds, it has not been run there); the adapters that were written from vendor documentation and not run (Codex CLI, Cursor, Gemini CLI, Copilot CLI, Windsurf, Devin). A model review is not a substitute for an external audit.
