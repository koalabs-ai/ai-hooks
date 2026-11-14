# AGENTS.md

Instructions for a coding agent. Two parts: how to install and wire **ai-hooks** for the user, and how to work on this repository.

## 1. Install ai-hooks and wire it into the agent harness

ai-hooks keeps secrets out of agent transcripts: a **guard** that blocks commands likely to print secrets, and a **redactor** that replaces secret-shaped strings with `<REDACTED:type:fingerprint>`. One static binary, no network access, no telemetry.

Every command below is idempotent: running it twice changes nothing the second time, and `uninstall` removes exactly what `install` wrote. Add `--dry-run` to see what would change.

### Install the binary

```sh
# Go 1.22+
go install github.com/koalabs-ai/ai-hooks/cmd/ai-hooks@latest
# or a checksum-verified release binary
curl -fsSL https://raw.githubusercontent.com/koalabs-ai/ai-hooks/main/install.sh -o /tmp/ai-hooks-install.sh && sh /tmp/ai-hooks-install.sh
ai-hooks version
```

### Wire it in (pick the harness the user runs)

| Harness | Command | Status |
|---|---|---|
| Claude Code | `ai-hooks install claude` | verified: guard + output redaction |
| Kimi Code | `ai-hooks install kimi` | verified: guard only |
| opencode | `ai-hooks install opencode` | verified: guard + output redaction |
| Codex CLI | `ai-hooks install codex` | from vendor docs, not run |
| Cursor | `ai-hooks install cursor` | from vendor docs, not run (guard only) |
| Gemini CLI | `ai-hooks install gemini` | from vendor docs, not run (guard only) |
| GitHub Copilot CLI | `ai-hooks install copilot` | from vendor docs, not run |
| Windsurf / Devin | `ai-hooks install windsurf`, `ai-hooks install devin` | from vendor docs, not run (guard only) |
| Any MCP client (Cline, Continue, Amp, Zed, ...) | register the server `ai-hooks mcp` (see below) | verified with Claude Code's MCP client |
| Anything else | `ai-hooks exec -- <cmd>` or `<cmd> 2>&1 \| ai-hooks redact` | verified |

Add `--project` to write the project's config instead of the user's. After installing, tell the user to restart the agent so it reads the new config. Check it works:

```sh
ai-hooks guard -- 'docker inspect web'; echo "exit $?"     # exit 2 and a one-line instruction
printf 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n' | ai-hooks redact   # key replaced by <REDACTED:aws-access-key:...>
ai-hooks test --short
```

### MCP server (no hooks needed)

```sh
claude mcp add ai-hooks -- ai-hooks mcp                      # Claude Code
# any other client: command "ai-hooks", args ["mcp"], transport stdio
```

Tools: `guard`, `redact`, `scan`, `safe_run`. To disable command execution use `ai-hooks mcp --no-run`; to restrict it, `--allow-run '^(ls|git) '`.

### A shell shim for harnesses with no hook mechanism

```sh
mkdir -p ~/.config/ai-hooks && ai-hooks shell-init bash > ~/.config/ai-hooks/shell.sh
export BASH_ENV=~/.config/ai-hooks/shell.sh     # non-interactive bash used by agents
```

### CI

```yaml
- uses: koalabs-ai/ai-hooks@v0.1.0
  with:
    scan-path: .          # writes ai-hooks.sarif; upload it with github/codeql-action/upload-sarif
```

### Rules for the agent itself

- Do not append `# noredact` or `# ai-hooks: ok` to commands. They are for the user.
- If a command is blocked, repeat it through `ai-hooks redact` as the message says; do not look for another way to print the same value.
- Never paste real secrets into issues, pull requests, tests or corpus files. Use fake values.

## 2. Working on this repository

- Go 1.22 or newer, standard library only, no cgo. `make test` (vet, gofmt check, tests), `make selftest` (runs the bundled corpus), `make cross` (static binaries).
- Layout: `cmd/ai-hooks` CLI; `internal/redact` detectors; `internal/guard` rules (`rules.json` embedded) and the shell-aware analysis; `internal/adapters` hook protocols and `install`; `internal/mcp` MCP server; `internal/report` text/JSON/SARIF; `corpus/` fake secrets (templates, expanded at test time).
- A new detector needs a positive case and a negative case in `corpus/`, and an entry in `internal/redact/explain.go` (or the `desc` field in `extra.go`). `ai-hooks test` must report no missed secret and no new false alarm.
- A new guard rule is data: add it to `internal/guard/rules.json` with a test in `internal/guard/rules_test.go` (one command that must be blocked, one near-miss that must pass).
- The guard fails open and the redactor never fails the pipeline: keep it that way. Do not add network access or non-stdlib dependencies.
- Behaviour of the original detectors is pinned by `AI_HOOKS_PARITY=1`; see `docs/PARITY.md`.
- Docs: `docs/DESIGN.md`, `docs/SECURITY-MODEL.md`, `docs/STANDARDS.md`, `docs/DETECTORS.md`.
