# ai-hooks: design note

**ai-hooks keeps secrets out of what an AI coding agent sees, by blocking commands that are likely to print them and by replacing secret-shaped strings in output with a stable placeholder.**

## Two functions

**Guard** (`ai-hooks guard`, and the PreToolUse side of the adapters). Before a shell command runs, decide whether it is likely to print secret values. If so, refuse with one line that says how to repeat it safely (usually: pipe it through `ai-hooks redact`). The override is explicit (`# noredact` or `# ai-hooks: ok` at the end of the command) and is written to a local log, with the command itself redacted.

**Redact** (`ai-hooks redact`, `ai-hooks exec`, and the PostToolUse side of the adapters). A filter from text to text. Secret-shaped strings become `<REDACTED:type:fingerprint>`. The fingerprint is the first 8 hex digits of an HMAC-SHA256 of the value under a per-install random key, so the same secret is recognisable on every line (and across runs on that machine) without being revealed, and a weak secret cannot be confirmed from the fingerprint (see `docs/SECURITY-MODEL.md`). `--json` reports how many values of each type were replaced, never the values.

Redaction has two layers, applied in this order:

1. **By value**: a file of `sha256 label` lines (`AI_HOOKS_KNOWN_HASHES`). A token with no recognisable shape is still caught if you registered its hash. The file holds hashes, never values.
2. **By shape**: 113 detectors (cloud and API keys, tokens of the common providers, JWTs, PEM/OpenSSH/PGP/PuTTY private keys, passwords in URLs and connection strings, headers, cookies, `.netrc`, TOTP seeds, `NAME=value` where the name says secret or the value has high entropy). `ai-hooks explain` lists them; `docs/DETECTORS.md` is the table.

Before matching, the text is normalised (ANSI colour codes and zero-width characters removed; `\uXXXX`, `\xNN` and `%XX` escapes decoded; UTF-16 input decoded). Text with no finding is returned exactly as it came; text with a finding is returned normalised and redacted.

## Threat model

The thing being protected is the **transcript**: whatever a coding agent reads is sent to a model provider and stored in session logs. Secrets that reach it also reach, through the agent, pull-request bodies, commit messages, chat messages and shared screens. The usual accident is not an attack but a helpful command: `cat .env`, `journalctl -u app`, `docker inspect`, `printenv`, `curl -v` with a token in a header.

Non-goals, stated plainly:

- It is not a secret manager. It does not store, rotate or inject secrets.
- It is not a guarantee. Detection is by shape; a secret with no shape and no registered hash passes (see `ai-hooks test`: known misses).
- It does not stop a malicious or compromised agent. An agent that wants the value can encode it (base64, split it, write it to a file and read it back) or turn the guard off.
- It does not scan repositories or git history. Use a scanner for that (see the comparison in the README); the two are complementary.

## Guard rules

Two kinds.

**Redact rules** are data (`internal/guard/rules.json`, embedded, same format for the user file). A rule fires when every regex in `match` matches some line of the lower-cased command, none of `unless` does, and the command is not already piped through `ai-hooks redact`/`exec`:

```json
{"id": "journalctl-unit", "why": "journalctl -u can contain environment dumps with secrets",
 "match": ["\\bjournalctl\\s.*(-u|--unit)\\s"]}
```

A user file (`$AI_HOOKS_RULES`, default `<config dir>/ai-hooks/rules.json`) is merged on top. It can add `redact_rules`, add `secret_paths` (regex alternatives for "a file that holds secrets"), `disable` rule ids (also the structural ones) and `allow` (a command matching any of these regexes is never blocked). A broken user file is ignored and the defaults stay.

**Structural rules** need to understand the shell a little (pipes, quotes, heredocs, `ssh '...'` bodies, `$(...)`), so they are code, not data. They find a secret file or variable that reaches the terminal:

| id | what it catches |
|---|---|
| `print-secret-file` | `.env`-style files and `/proc/*/environ` read by `cat`, `grep`, `sed`, `awk`, ... |
| `echo-secret-var` | `echo $DB_PASSWORD` to the terminal |
| `dump-env` | `env`, `printenv`, `docker inspect`, `systemctl show -p Environment`, `declare -p` |
| `xtrace` | `set -x` / `bash -x` around something that touches secrets |
| `curl-verbose` | `curl -v` with a secret variable in a header (the trace goes to stderr) |
| `background-secret` | a secret expanded into argv of a backgrounded command (visible in `ps`) |

A command is safe when its output goes to a sink that hides values: `ai-hooks redact` or `exec`, names only (`cut -d= -f1`), a count or hash (`wc`, `grep -c`, `sha256sum`), or `/dev/null`. Shell comments are removed before the analysis (a `#` that starts a word, outside quotes), so comment text such as `# wc -l` does not make a command look safe. The override comments (`# noredact`, `# ai-hooks: ok`) must be the last thing on the command; `AI_HOOKS_NO_OVERRIDE=1` ignores them.

The guard **fails open**: an internal error, an unreadable payload or a pathological command (it has a work budget) allows the command. A guard that can wedge the agent gets switched off.

## Messages and locale

Messages live in a catalog per language (`AI_HOOKS_LANG`). Only English ships. Adding a language is a map of two strings (`guard.RegisterCatalog`).

## Adapters

Every harness gets the same core through `ai-hooks hook <harness>`: a JSON payload on stdin, a decision on stdout.

| harness | before a command | after a command |
|---|---|---|
| Claude Code | `PreToolUse` on `Bash`: JSON `permissionDecision: deny` with the one-line reason | `PostToolUse`: `updatedToolOutput` replaces what the model sees with a redacted copy of the same shape |
| Kimi Code | `PreToolUse` on `Bash`, same payload and answer | not available: the harness cannot rewrite tool output. Use `ai-hooks exec` or a pipe |
| opencode | a plugin (`tool.execute.before` throws to block) | the same plugin rewrites the tool result |
| Codex CLI, Cursor, Gemini CLI, Copilot CLI, Windsurf, Devin | each vendor's documented hook (implemented from the docs, not run) | Codex and Copilot only |
| MCP clients | `guard` tool | `redact`, `scan` and `safe_run` tools |
| any shell | `ai-hooks guard` (exit 0 allow, 2 block) | `ai-hooks redact` (pipe) or `ai-hooks exec -- cmd` (guard, run, redact, keep the exit code) |

Harnesses with no verified adapter are listed as untested in the README rather than claimed.

## Why Go, and what the port is

One static binary, no cgo, a few milliseconds to start (`make latency`): it runs before and after every shell command, so start-up cost is the product. Patterns compile on first use, and most detectors are skipped by a literal pre-check, so a typical command output pays for almost none of them. The shape detectors descend from a Python implementation; Go's RE2 has no lookaround, so each lookbehind and lookahead is rebuilt as an explicit check, and the result was verified byte-identical to the original on synthetic and real text (`docs/PARITY.md`). The one intended difference is that a bare 32-hex value is not redacted when the same line names an invocation id, md5, checksum, etag, trace id or similar (`AI_HOOKS_PARITY=1` turns that off).

## Layout

```
cmd/ai-hooks/       the CLI
internal/redact/    detectors, fingerprints, known-value layer, streaming
internal/guard/     rules.json (embedded), structural analysis
internal/adapters/  hook protocols, install/uninstall, override log
internal/mcp/       MCP server (guard, redact, scan, safe_run)
internal/report/    text, JSON and SARIF output
internal/selftest/  runs the corpus
corpus/             FAKE secrets and clean samples (positive.jsonl, negative.jsonl)
```
