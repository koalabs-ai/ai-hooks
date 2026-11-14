# Security policy

ai-hooks reduces the chance that secrets reach an AI agent's transcript. It is not a guarantee: read [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) for what it does and does not stop. Problems with it are taken seriously.

## What to report privately

- A way to get a secret past the guard or the redactor that is **systematic** (a class of commands, an encoding, an input format), not a single missing provider format. Missing formats are welcome as public issues with a FAKE example.
- A bug where ai-hooks itself writes or sends a secret somewhere (logs, reports, error messages, network).
- A crash, hang or memory blow-up in a hook, the MCP server or `scan` that could block or exhaust an agent.
- A way to make `ai-hooks install`, `uninstall` or `safe_run` do something outside their documented behaviour (write elsewhere, clobber a config, run what the guard blocks).
- A weakness in `install.sh`, the release artifacts or the GitHub Action.

## How

Use **"Report a vulnerability"** in the Security tab of this repository (GitHub private vulnerability reporting): <https://github.com/koalabs-ai/ai-hooks/security/advisories/new>. Please include a FAKE reproduction. Do not send real secrets or real transcripts.

## What to expect

An acknowledgement within a few days, and a fix or a documented limit in the next release. Credit in the release notes if you want it.

## Supported versions

Only the latest release.

## Review history

The pre-release review (models, static analysis, adversarial tests) is summarised in [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md).
