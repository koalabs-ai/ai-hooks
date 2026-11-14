#!/usr/bin/env bash
# Cold-start latency of the hot paths. Each case is N process launches (fresh
# process every time); prints mean and p95 in milliseconds.
# usage: scripts/latency.sh [path-to-ai-hooks] [N]
set -euo pipefail
BIN="${1:-dist/ai-hooks}"; N="${2:-300}"
python3 -I - "$BIN" "$N" <<'PY'
import subprocess, sys, time, statistics, json
bin_, n = sys.argv[1], int(sys.argv[2])
pre = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls -la && git status"}})
pre_block = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "journalctl -u app -n 50"}})
post = json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": {"stdout": "total 4\nREADME.md\n", "stderr": ""}})
cases = [
    ("version", [bin_, "version"], ""),
    ("redact (small text)", [bin_, "redact"], "hello world\n"),
    ("guard (allowed command)", [bin_, "guard", "--", "ls -la"], ""),
    ("hook claude PreToolUse, allowed", [bin_, "hook", "claude"], pre),
    ("hook claude PreToolUse, blocked", [bin_, "hook", "claude"], pre_block),
    ("hook claude PostToolUse, clean output", [bin_, "hook", "claude"], post),
]
print(f"{'case':38} {'mean ms':>8} {'p95 ms':>8}   (n={n})")
for name, cmd, stdin in cases:
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        subprocess.run(cmd, input=stdin.encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ts.append((time.perf_counter() - t) * 1000)
    ts.sort()
    print(f"{name:38} {statistics.mean(ts):8.2f} {ts[int(len(ts)*.95)-1]:8.2f}")
PY
