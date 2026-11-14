# ai-hooks

**Stop AI coding agents from leaking secrets into their transcripts.** A command guard and an output redactor in one static Go binary, for Claude Code, Kimi Code, opencode, any MCP client and any shell. No network access, no telemetry.

[![CI](https://github.com/koalabs-ai/ai-hooks/actions/workflows/ci.yml/badge.svg)](https://github.com/koalabs-ai/ai-hooks/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/koalabs-ai/ai-hooks)](https://github.com/koalabs-ai/ai-hooks/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/koalabs-ai/ai-hooks.svg)](https://pkg.go.dev/github.com/koalabs-ai/ai-hooks)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

An agent runs `cat .env` or `journalctl -u app`, and every key in the output is now in the model provider's logs and your session history. ai-hooks refuses the risky command with a one-line fix, and replaces anything secret-shaped in the output with `<REDACTED:type:fingerprint>`, so the agent keeps working without ever seeing the value.

<picture>
  <source media="(prefers-color-scheme: light)" srcset="demo/out/ai-hooks-demo-light.gif">
  <img alt="Terminal demo: cat .env leaks a fake AWS key; the same command through ai-hooks redact shows <REDACTED:aws-access-key:...> and leaves user=john untouched; the guard blocks journalctl -u; the bundled tests print the detection numbers." src="demo/out/ai-hooks-demo-dark.gif" width="860">
</picture>

```sh
go install github.com/koalabs-ai/ai-hooks/cmd/ai-hooks@latest    # or: curl -fsSLO https://raw.githubusercontent.com/koalabs-ai/ai-hooks/main/install.sh && sh install.sh
ai-hooks install claude        # claude | kimi | opencode | codex | cursor | gemini | copilot | windsurf | devin; restart the agent
```

| Harness | Setup | Guard (blocks a command) | Redacts output | Status |
|---|---|---|---|---|
| Claude Code | `ai-hooks install claude` | yes | yes | **verified** |
| opencode | `ai-hooks install opencode` | yes | yes | **verified** |
| Kimi Code | `ai-hooks install kimi` | yes | no (not possible in its hooks) | **verified** |
| Any MCP client | `ai-hooks mcp` (tools `guard`, `redact`, `scan`, `safe_run`) | on request | on request | **verified** with Claude Code's MCP client |
| Any shell, any agent | `ai-hooks exec -- cmd`, `cmd \| ai-hooks redact`, `ai-hooks shell-init` | yes | yes | **verified** |
| Codex CLI, Cursor, Gemini CLI, Copilot CLI, Windsurf, Devin | `ai-hooks install <name>` | yes | Codex and Copilot only | implemented from the vendors' docs (2026-11-13), **not run** |
| Cline, Continue, Amp, Aider | MCP server, `exec` or the shell shim | via those | via those | no native hook used |

"Verified" means run for real on one machine in a live agent session, with the result read back from the session. Nothing else is claimed.

## Questions people (and agents) ask

**How do I stop Claude Code from printing secrets?** `ai-hooks install claude` adds a `PreToolUse` hook that blocks risky `Bash` commands with a reason the model reads, and a `PostToolUse` hook that rewrites the output the model sees. See [the Claude Code guide](site/claude-code.html) for a working hook example.

**My AI agent leaked an API key in the transcript. What now?** Rotate the key first: redacting afterwards does not unsend it. Then install a guard so it cannot happen the same way again.

**How do I redact secrets from terminal output?** `cmd 2>&1 | ai-hooks redact`, or `ai-hooks redact --stream` for a live log.

**Is there a secret scanner for AI agent output?** That is what the redactor and the `PostToolUse` hook are. For files and CI, `ai-hooks scan --format sarif` writes SARIF 2.1.0.

**Does it send anything anywhere?** No. No network calls, no telemetry; the tests run it with networking disabled. See [the security model](docs/SECURITY-MODEL.md).

**What does it not do?** It is not a guarantee, not a sandbox and not a secret manager. [Limits](#limits).

## What it does

**Guard.** Before a command runs it looks for the usual accidents and refuses with one line saying how to repeat it safely: reading `.env` and credential files (`~/.aws/credentials`, `.netrc`, `.npmrc`, keys), `journalctl -u`, `systemctl cat`, `docker inspect`, `docker compose config`, `printenv`/`env`, `kubectl get secret` and `config view --raw`, `terraform output/show`, cloud CLIs that print tokens (`aws`, `gcloud`, `az`, `gh auth token`), secret managers (`vault`, `op`, `bw`, `pass`, `sops`), `git config --list`, shell history, `ps e`, `/proc/*/environ`, `curl -v` with a token, `set -x` around secrets, and the same inside `ssh '...'`, `sh -c`, `eval`, heredocs and `$(...)`. `ai-hooks rules list` shows all 33 rules. A command is fine when its output goes through `ai-hooks redact`, to a names-only filter (`cut -d= -f1`), to a count or hash, or to `/dev/null`. Overrides (`# noredact`, `# ai-hooks: ok`) are explicit and logged; `AI_HOOKS_NO_OVERRIDE=1` turns them off. Add your own rules in a JSON file ([schema](internal/guard/rules.schema.json)).

**Redactor.** A filter from stdin to stdout with 113 detectors ([list](docs/DETECTORS.md)): cloud (AWS, Google Cloud, Azure, DigitalOcean, Cloudflare), AI providers (OpenAI, Anthropic, Hugging Face, Groq, OpenRouter, xAI and more), code hosts and registries (GitHub, GitLab, npm, PyPI, crates.io, Docker Hub), payments, chat and email, infrastructure (Tailscale, Vault, Terraform, Kubernetes), private keys (PEM, OpenSSH, PGP, PuTTY, age, WireGuard), JWTs, passwords in URLs and connection strings, headers, cookies, `.netrc`, TOTP seeds and `NAME=value` with a high-entropy value; optional Luhn-checked card numbers. The same secret always gets the same fingerprint (a keyed hash: [how](docs/SECURITY-MODEL.md#fingerprints)), so two lines can be recognised as holding one value without revealing it. It sees through ANSI colour codes, zero-width characters, `\uXXXX`/`%XX` escapes and UTF-16 input. `--json` reports counts by type, never values. Register values with no recognisable shape by sha256 (`AI_HOOKS_KNOWN_HASHES`).

**Also:** `ai-hooks scan` (text, JSON or SARIF 2.1.0; exit 1 on findings), a GitHub Action ([`action.yml`](action.yml)), an agent skill ([`skills/ai-hooks`](skills/ai-hooks/SKILL.md)), a Claude Code plugin (`.claude-plugin/`), and machine-readable output everywhere (`rules list --json`, `rules schema`, documented exit codes). Agents: see [AGENTS.md](AGENTS.md) and [llms.txt](llms.txt).

## Numbers

Measured on one machine (Intel Core Ultra 7 155H, 22 threads, Linux 7.2, Go 1.27.4) while it was busy with other work, so read them as conservative. Re-run with `make selftest`, `make latency`.

| | |
|---|---|
| Detection, bundled corpus | **123/123** fake secrets redacted, across 113 detector types ([table by type](docs/DETECTION.md)) |
| False alarms, bundled corpus | **0/43** clean samples touched (git SHAs, UUIDs, systemd invocation ids, lockfile hashes, base64 images, placeholders, prose, code) |
| Known misses | 5, listed by `ai-hooks test` |
| Known false alarms | 2, listed by `ai-hooks test` |
| Binary | 3.9 MB (linux/amd64, stripped, static, no dependencies); 3.7 to 4.1 MB on the other platforms |
| Cold start | a hook call for an allowed command: **5.2 ms** mean (6.1 ms p95, 150 launches) when the machine was lightly loaded, against 4.0 ms for a bare `ai-hooks version`. Measured again at load average 12 (the machine stayed busy): bare start 13.0 ms, hook for an allowed command 13.7 ms, `redact` on a small text 18.9 ms, hook with output to rewrite 18.2 ms. In every run the tool adds roughly 1 to 6 ms to the cost of starting a process; the Python original it descends from took about 91 ms |
| Throughput | `redact` on a 10 MB log with a few secrets: 9 to 12 s of CPU at load average 17 (about 1 MB/s), roughly 1.3 times the original detector set alone. Built for command output (kilobytes), not for log archives; speeding up the older detectors is future work |
| Output vs the original shape detectors | byte-identical on 20,000 synthetic texts and 10,098 real text files in compatibility mode ([parity](docs/PARITY.md)) |

The corpus is small and written by the authors: it shows each detector does what it says on its known shapes, not how the tool does on your data. False-alarm reports with a fake example are the most useful contribution there is.

## Limits

- **Not a guarantee.** Detection is by shape. Known misses: a bare `TOKEN=value`, a base64- or hex-encoded key, a key split across lines or by spaces, a password in free prose, values under the minimum length.
- **Known false alarms.** A bare 32-hex value followed by a space is shaped like a Twilio auth token (an `md5sum` line is redacted; invocation ids, md5 and etag values are skipped when the line says what they are). `password = getpass.getpass(...)` in code is redacted as a password assignment.
- **A deliberate agent can get around it.** It can encode the output, split it, write it to a file and read it back, use a tool the hooks do not see, or edit its own hook configuration. ai-hooks stops accidents, not attacks; it is not a sandbox. [Details](docs/SECURITY-MODEL.md).
- **Only what the hooks see.** Shell commands, and the tools the MCP server exposes. The agent's own file-read tool and other tools' output are not covered.
- **Opaque commands.** Aliases, computed `eval` strings, scripts that read a secret and print it, and `X=$(cat file); echo "$X"` are not understood by the guard.
- **Redaction happens after the command ran.** Side effects have happened; only what the model sees changes. Rotate anything that already leaked.
- **Kimi Code, Cursor, Gemini CLI, Windsurf and Devin** cannot rewrite tool output: they get the guard only. Use `ai-hooks exec` for the other half.
- **`safe_run` / `exec` run commands as you.** Not a sandbox; `ai-hooks mcp --no-run` turns it off, `--allow-run REGEX` restricts it.
- **Windows:** the binary builds for Windows; it has not been run there and the shell shim is bash/zsh only.
- Not a secret manager. `scan` is a lightweight file scanner, not a history scanner.

## How it compares

| | Scans | When | Output |
|---|---|---|---|
| gitleaks, trufflehog, detect-secrets | repositories, git history, files | at commit, in CI, on demand | a report of findings (trufflehog can also check whether a credential is live) |
| **ai-hooks** | an agent's live shell commands and their output (and files, lightly, with `scan`) | before each command and after it, while the agent works | blocks the command, or masks the output |

They are complementary: use both. This repository is itself scanned with gitleaks in CI, with an allowlist for the intentional fakes in `corpus/`. Several other projects guard agents for one harness or redact in a proxy; ai-hooks is one static binary that does both halves and works across harnesses.

## FAQ

**Can I see the raw value when I really need it?** Append `# noredact` to the command. It runs, and the override is logged (command redacted, no output). `AI_HOOKS_NO_OVERRIDE=1` disables that.

**How do I add a provider?** Add a fake example to `corpus/positive.jsonl`, add the detector in `internal/redact/extra.go`, run `make test`. See [CONTRIBUTING.md](CONTRIBUTING.md).

**How do I undo `install`?** `ai-hooks uninstall <harness>` removes the entries it added and leaves the rest of the file alone; the original file is also saved once as `<file>.ai-hooks-bak`.

**Why Go?** It runs before and after every shell command, so start-up time is the product: one static binary, a few milliseconds.

**Which languages are the messages in?** English. There is a catalog mechanism (`AI_HOOKS_LANG`, `guard.RegisterCatalog`) for adding more.

## Docs

[Design](docs/DESIGN.md) · [Security model](docs/SECURITY-MODEL.md) · [Standards mapping](docs/STANDARDS.md) (OWASP, CWE, NIST, ISO 27001, PCI, SARIF; a mapping, not a compliance claim) · [Detectors](docs/DETECTORS.md) · [Detection table](docs/DETECTION.md) · [Parity](docs/PARITY.md) · [Security review](docs/SECURITY-REVIEW.md) · [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## License

Apache-2.0, see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

---

Built and used daily at [KOA Labs](https://koalabs.ai).
