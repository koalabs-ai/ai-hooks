# Contributing to ai-hooks

Thanks for helping. The most useful contributions are small and come with a test case.

## The two most welcome kinds

**A missed secret.** A credential format ai-hooks does not catch.
1. Add a line to `corpus/positive.jsonl` with a FAKE value. Use the vendor's documented example if there is one; otherwise a template: `[[` and `]]` mark the secret, and `{{alnum:24}}`, `{{hexl:32}}`, `{{b64url:40}}`, `{{digits:10}}`, `{{upper:16}}`, `{{b64:30}}` expand to deterministic pseudo-random characters. This keeps secret-shaped literals out of the repository.
2. Run `make selftest`: the new line should show as missed.
3. Add the detector to the table in `internal/redact/extra.go` (pattern, description, and a `needs` literal so it is skipped on text that cannot match). Prefer a provider prefix to a generic shape. Then run `make docs` to refresh `docs/DETECTORS.md` and `docs/DETECTION.md`.
4. Add at least one negative case in `corpus/negative.jsonl` for the nearest harmless text, then run `make test`.

**A false alarm.** Something harmless was redacted or blocked. Add it to `corpus/negative.jsonl`, make it pass, and make sure no positive case stops passing. If the fix would lose real detections, record it as `"known_false_alarm": true` with a note, which is the honest option.

## Rules

- **FAKE secrets only.** Never paste a real secret, a real `.env`, or a real transcript, in an issue, a pull request or a test. If you are unsure whether something is real, treat it as real.
- Run `make test` before sending a change. CI also runs gitleaks; intentional fakes live under `corpus/` and are allow-listed there.
- No new dependencies unless there is a strong reason: the binary is static and starts in milliseconds, and that is the product.
- Behaviour of `ai-hooks redact` is output-compatible with the shape detectors it descends from (`docs/PARITY.md`). A change that alters output on existing text needs a corpus line that shows why.
- The guard fails open. Keep it that way.

## Development

```
make test        # vet, gofmt check, unit tests
make selftest    # build and run the bundled corpus
make cross       # linux/darwin x amd64/arm64 static binaries in dist/
make demo        # re-render the GIF and stills in demo/out/
make docs        # regenerate docs/DETECTORS.md and docs/DETECTION.md
```

Go 1.22 or newer. No cgo.

## Security issues

A way around the guard, or a leak caused by ai-hooks itself: see `SECURITY.md`, not a public issue.

By contributing you agree your work is licensed under Apache-2.0 (see `LICENSE`).
