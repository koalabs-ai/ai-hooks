---
name: ai-hooks
description: Use when running shell commands that may print secrets (reading .env or credential files, journalctl -u, docker inspect, printenv, kubectl get secret, terraform output, cloud CLI token commands) and when you must show command output or logs to the user or paste them anywhere. Runs the command through ai-hooks so secret-shaped values are replaced by <REDACTED:type:fingerprint>, and explains what to do when a command is blocked.
license: Apache-2.0
compatibility: Needs the ai-hooks binary on PATH (https://github.com/koalabs-ai/ai-hooks). No network access.
metadata:
  homepage: https://github.com/koalabs-ai/ai-hooks
---

# ai-hooks: keep secrets out of the transcript

Anything you print ends up in the transcript, which is sent to the model provider and stored. Do not print secret values. Use the tool for commands that might.

## When to use it

- Before running a command that may print credentials: `cat .env`, `cat ~/.aws/credentials`, `journalctl -u <unit>`, `systemctl cat/show`, `docker inspect`, `docker compose config`, `printenv`, `env`, `kubectl get secret -o yaml`, `terraform output`, `aws/gcloud/az ... get token`, `gh auth token`, `git config --list`.
- Before pasting logs or command output into a message, a pull request, an issue or a commit message.

## How

1. Run the command through the wrapper (the guard checks it first, the output is redacted, the exit code is kept):

   ```sh
   ai-hooks exec -- journalctl -u app -n 100
   ```

   or pipe: `journalctl -u app -n 100 2>&1 | ai-hooks redact`

2. If a command is blocked with a message starting `ai-hooks [rule-id]:`, do **not** try to get around it. Repeat the command through `ai-hooks redact` as the message says. Use names only (`cut -d= -f1 .env`) or a count/hash (`wc -l`, `sha256sum`) when you do not need values.

3. A redacted value looks like `<REDACTED:aws-access-key:5a976826>`. The same value always has the same fingerprint, so you can tell whether two lines hold the same secret without seeing it. You almost never need the value itself; if you think you do, ask the user.

4. Never append `# noredact` or `# ai-hooks: ok` yourself. Those are overrides for the user.

## If this is an MCP client

The `ai-hooks mcp` server exposes `guard` (is this command safe to run?), `redact` (mask secrets in text), `scan` (find secrets in text) and `safe_run` (run a command, guarded and redacted).

## Limits

It masks by shape. It does not catch a password in prose, a base64-encoded key or a value it has no pattern for, and it is not a sandbox. Do not rely on it to make an unsafe command safe.
