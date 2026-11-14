# Security model

What ai-hooks protects, what it does not, and how it behaves when something goes wrong. Read this before relying on it.

## What it is for

A cooperative coding agent runs commands to do its job. Some of those commands print secrets (`cat .env`, `journalctl -u`, `docker inspect`, `printenv`, a `curl -v` with a token in a header). The output is sent to a model provider and kept in session history. ai-hooks reduces **accidental** leakage by a **cooperative** agent: it blocks the commands that usually do this and masks secret-shaped strings in what comes back.

## What it does not stop

- **A malicious or prompt-injected agent that wants the secret.** It can encode the value (base64, hex, split it, reverse it), write it to a file and read it back, read it with a tool the hooks do not cover (the agent's own file-read tool, an MCP tool, a browser), or edit the hook configuration. The guard is a seatbelt, not a sandbox. If you need containment, run the agent in a sandbox that does not hold the secrets.
- **A writable configuration.** The hook configuration and the rules file are plain files the agent's user can write. An agent that edits them can switch the guard off or add `allow` rules.
- **Overrides.** `# noredact` and `# ai-hooks: ok` exist for a person who knows the output is safe. Text an agent has read could suggest them, so in a setting where agents read untrusted text set `AI_HOOKS_NO_OVERRIDE=1` (strict mode: no comment switches the guard off). Overrides are logged either way.
- **Secrets with no recognisable shape.** Detection is by shape (prefixes, labels, structures) plus values you register by hash. A password in prose, a bare `TOKEN=value`, a base64-encoded key and a key split across lines pass. `ai-hooks test` lists the known misses.
- **Anything the hooks never see.** Only shell commands (and, with the MCP server, the tools it exposes). Output of other tools, files the agent reads directly, and text the user types are not covered.
- **A deliberately opaque command.** Shell aliases and functions, `eval` of computed strings, `bash -c "$(echo ... | base64 -d)"`, scripts that read a secret and print it (`python3 script.py`), `X=$(cat file); echo "$X"`, and file-name obfuscation (`cat .e*`) are not understood by the guard. The redactor still masks shaped secrets in their output when a PostToolUse hook, `exec` or a pipe is in place.
- **Data after the fact.** Redaction runs after the command ran: side effects have happened, and a secret that already reached a transcript stays there. Rotate it.

## How the pieces behave

| Component | Does | Fails how |
|---|---|---|
| Guard | decides from the command text; no execution | **open**: an internal error, an unreadable payload, a command over 4 MB, or an exhausted analysis budget allows the command |
| Redactor | text to text; patterns are Go RE2 (linear time, no backtracking) | always exits 0 so a pipeline never breaks, even on a read error (output may then be incomplete); memory is bounded in `--stream` mode (lines over 4 MB are cut at whitespace, which can split a label from its value; private-key blocks over 1 MB are replaced) |
| Hook adapters | map a harness's payload to the guard and redactor | allow on a payload they cannot parse |
| `install` | edits the harness config | refuses invalid JSON, backs up the original once, edits only its own entries, keeps symlinks and file modes, creates files `0600` |
| MCP server | `guard`, `redact`, `scan`, `safe_run` over stdio | `safe_run` is a command-execution primitive by design: see below |

### Input normalisation

Before matching, `redact` looks through what hides a secret from a pattern without changing what a reader sees: ANSI colour codes and OSC sequences, zero-width characters (U+200B/C/D, U+2060, U+FEFF, soft hyphen), `\uXXXX`, `\xNN` and `%XX` escapes, and UTF-16 or BOM-prefixed input (decoded to UTF-8 by the command-line readers). Text with no finding is returned **exactly** as it came; text with a finding is returned normalised (colour codes and zero-width characters removed, escapes decoded) and redacted.

### Fingerprints

A fingerprint (`<REDACTED:type:5a976826>`) is the first 8 hex digits of **HMAC-SHA256(key, value)**. The key is 32 random bytes created on first use in `<state dir>/ai-hooks/fingerprint.key` (mode `0600`) or taken from `AI_HOOKS_FINGERPRINT_KEY`. Consequences:

- The same value has the same fingerprint on every line and in every run on that machine, so you (and the agent) can tell two lines hold the same value without learning it.
- It is **not** reversible, and because it is keyed it cannot be used by someone who only sees the transcript to confirm a guess at a weak secret (with a plain truncated hash, `hunter2` could be checked against it). Someone who can also read the key file on your machine could; the key is stored `0600`, and an agent running as you can read it, which is one more reason this is not a defence against a hostile agent.
- It differs between machines and after deleting the key. It is 32 bits, so collisions between different secrets are possible but harmless.
- `AI_HOOKS_FINGERPRINT=plain` (and `AI_HOOKS_PARITY=1`) use the original construction, the first 8 hex digits of sha256(value). That is stable everywhere and guessable for weak secrets.
- If the key cannot be stored (read-only home), the plain construction is used rather than a key that changes on every run.

### What ai-hooks itself writes

- Reports (`--json`, `scan`, SARIF) hold types, locations and fingerprints, never values.
- The override log (`<state dir>/ai-hooks/overrides.log`, `0600`) holds a timestamp, the rule, which override was used and the command **after redaction**, cut to 300 characters. A secret with no recognisable shape inside an overridden command would appear there.
- No debug mode, no cache of inputs or outputs, no network access (the binary links no HTTP or TLS packages, and the tests run it with networking disabled). No telemetry.

### `safe_run` (MCP) and `exec`

`ai-hooks exec -- cmd` and the MCP `safe_run` tool run a command **as the user who started them**, after the guard has looked at it (treating it as piped through the redactor, so the usual "re-run it through the redactor" rules are satisfied) and with its output redacted. They are not a sandbox and add no privileges. For `safe_run`: input is validated (command at most 64 KiB, `cwd` an existing absolute directory, `timeout_seconds` 1 to 600, unknown fields rejected), output is capped (16 MiB read, 1 MiB returned, redacted before it is cut so a secret is never half-shown), and you can switch it off (`ai-hooks mcp --no-run`) or restrict it (`--allow-run REGEX`, repeatable). A prompt-injected agent that can call `safe_run` can run anything the user can; do not expose it to agents you do not already trust with a shell.

### Supply chain

- Runtime dependencies: none outside the Go standard library (`go.mod` has no `require` lines).
- Binaries are built with `CGO_ENABLED=0 -trimpath`; releases carry SHA-256 checksums and an SBOM.
- `install.sh` downloads the release archive and its `checksums.txt` from the same release and refuses to install on a mismatch (set `AI_HOOKS_SHA256` to pin the checksum yourself). The README fetches the script to a file first, rather than piping it into a shell, so you can read it. A checksum from the same origin as the archive protects against corruption and partial compromise, not against a compromised release.
- GitHub Actions in this repository are pinned to commit SHAs.

## Reporting a problem

Use "Report a vulnerability" in the repository's Security tab (private vulnerability reporting). See `SECURITY.md`. The review that preceded the first release is summarised in `docs/SECURITY-REVIEW.md`.
