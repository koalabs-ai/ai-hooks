#!/usr/bin/env python3
"""Generate the static site (no framework) into site/. Run: python3 site/build.py

Placeholders to fill at publish time (one command: scripts/set-site-url.sh <base-url> <repo-url>):
  https://koalabs-ai.github.io/ai-hooks     where the site is served, e.g. https://example.org/ai-hooks
  https://github.com/koalabs-ai/ai-hooks   the repository
"""
import html, json, os, shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = "https://koalabs-ai.github.io/ai-hooks"
REPO = "https://github.com/koalabs-ai/ai-hooks"
DATE = "2026-11-13"
TAGLINE = "Stop AI coding agents from leaking secrets into transcripts"
DESC = ("ai-hooks is a command guard and output redactor in one static Go binary. It blocks commands likely to print "
        "secrets and replaces secret-shaped strings in output with <REDACTED:type:fingerprint>. Verified with Claude Code, Kimi Code, opencode and MCP clients; works in any shell. No network access.")

NAV = [("index.html", "Home"), ("claude-code.html", "Claude Code"), ("kimi-code.html", "Kimi Code"),
       ("opencode.html", "opencode"), ("codex-cli.html", "Codex CLI"), ("cursor.html", "Cursor"),
       ("mcp.html", "MCP"), ("any-shell.html", "Any shell"), ("numbers.html", "Numbers"), ("faq.html", "FAQ")]

FAQ = [
    ("How do I prevent Claude Code from printing secrets?",
     "Add a PreToolUse and a PostToolUse hook on the Bash tool that run `ai-hooks hook claude`. The first blocks risky commands such as `cat .env` or `journalctl -u app` with a one-line instruction; the second rewrites the output the model sees so secret-shaped strings become <REDACTED:type:fingerprint>."),
    ("My AI agent leaked an API key in the transcript. What now?",
     "Rotate the key first: redacting afterwards does not unsend it. Then install a guard and a redactor so the same command cannot leak it again."),
    ("How do I redact secrets from terminal output?",
     "Pipe it through `ai-hooks redact`, for example `kubectl logs deploy/api 2>&1 | ai-hooks redact`. Use `--stream` to filter line by line, and `--json` to get counts by type without the values."),
    ("Is there a secret scanner for AI agent output?",
     "ai-hooks redact and its PostToolUse hook do that: a filter that masks secret-shaped strings in command output before the model reads it. Repository scanners such as gitleaks, trufflehog and detect-secrets solve a different problem (secrets in code and git history) and are complementary."),
    ("Does ai-hooks guarantee no secret reaches the model?",
     "No. Detection is by shape. A secret with no recognisable shape and no registered hash passes, and a deliberate agent can encode its output. The numbers page lists the known misses."),
    ("Does it send anything over the network?",
     "No. It reads standard input and writes standard output, plus an optional local log of overrides. No telemetry."),
    ("Which agents does it support?",
     "Verified in live sessions: Claude Code (guard and output redaction), opencode (guard and output redaction), Kimi Code (guard only), and any MCP client through `ai-hooks mcp` (tested with Claude Code's client). It also works in any shell through pipes, `ai-hooks guard` and `ai-hooks exec`. Codex CLI, Cursor, Gemini CLI, Copilot CLI, Windsurf and Devin are implemented from the vendors' documentation and have not been run."),
    ("Does it guarantee that no secret reaches the model?",
     "No. See the security model: detection is by shape, a deliberate agent can encode its output, and it only sees shell commands and the tools the MCP server exposes."),
]

PAGES = {}

def page(slug, title, desc, body, extra_ld=None, h1=None):
    PAGES[slug] = dict(title=title, desc=desc, body=body, ld=extra_ld or [], h1=h1 or title)

def e(s): return html.escape(s, quote=True)

def code(s): return "<pre><code>" + e(s.strip("\n")) + "</code></pre>"

HARNESS_NOTE_UNTESTED = ("<p class=\"warn\"><strong>Status: implemented from the vendor docs, not run.</strong> The vendor documents a hook mechanism, but ai-hooks has not been run "
                         "inside this harness, so no support is claimed. The pipe mode below works anywhere, and it is the verified fallback. "
                         "If you try it, an issue or pull request saying what happened is the most useful thing you can send.</p>")

# ---- home
home = f"""
<p class="lead">{e(DESC)}</p>
<picture><source media="(prefers-color-scheme: light)" srcset="assets/ai-hooks-demo-light.gif">
<img src="assets/ai-hooks-demo-dark.gif" width="860" alt="Terminal demo: cat .env leaks a fake AWS key; through ai-hooks redact it becomes REDACTED and user=john is untouched; the guard blocks journalctl -u; the bundled tests print 43/43 detected and 0/26 false alarms."></picture>
<h2>The problem</h2>
<p>A coding agent runs <code>cat .env</code> or <code>journalctl -u app</code>. Every key in the output is now in the model provider's logs, in your session history and, if you are unlucky, in a pull request. ai-hooks refuses the risky command with a one-line fix, and masks anything secret-shaped in the output, so the agent keeps working without ever seeing the value.</p>
<h2>Try it in 10 seconds</h2>
{code("printf 'user=john\\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\\n' | ai-hooks redact\n# user=john\n# AWS_ACCESS_KEY_ID=<REDACTED:aws-key-id:1a5d44a2>\n\nai-hooks guard -- 'journalctl -u app'   # exit 2, one line saying how to repeat it safely\nai-hooks test --short                    # detection and false-alarm rates on the bundled fake corpus")}
<h2>Install</h2>
{code("go install github.com/koalabs-ai/ai-hooks/cmd/ai-hooks@latest   # once the repository is public\n# or from a checkout:\nmake build && install -m 0755 dist/ai-hooks ~/.local/bin/ai-hooks")}
<h2>Guides by harness</h2>
<ul>
<li><a href="claude-code.html">Claude Code</a>: verified, guard and output redaction</li>
<li><a href="opencode.html">opencode</a>: verified, guard and output redaction</li>
<li><a href="kimi-code.html">Kimi Code</a>: verified, guard only</li>
<li><a href="mcp.html">MCP</a>: verified with Claude Code's client</li>
<li><a href="any-shell.html">Any shell</a>: verified, pipes and <code>ai-hooks exec</code></li>
<li><a href="codex-cli.html">Codex CLI</a>, <a href="cursor.html">Cursor</a> and others: implemented from the docs, not run</li>
</ul>
<h2>Numbers and limits</h2>
<p>On the bundled fake corpus: 43/43 secrets redacted, 0/43 clean samples touched, 5 known misses, 2 known false alarms. See <a href="numbers.html">numbers</a> for the machine and the method, and the <a href="faq.html">FAQ</a> for what it does not do.</p>
<p>Source: <a href="{REPO}">{REPO}</a> (Apache-2.0).</p>
"""
page("index.html", "ai-hooks: stop AI coding agents from leaking secrets", DESC, home, h1="ai-hooks")

# ---- harness pages
page("claude-code.html", "ai-hooks for Claude Code: stop it printing secrets",
     "How to stop Claude Code from printing secrets: a working PreToolUse and PostToolUse hook example with ai-hooks, verified on Claude Code 2.1.325.",
     f"""<p><strong>Status: verified</strong> on Claude Code 2.1.325: a real session was blocked from running <code>journalctl -u app</code>, and the output of a harmless command was rewritten before the model saw it.</p>
<h2>How to prevent Claude Code from printing secrets</h2>
<p>Add both hooks to <code>~/.claude/settings.json</code>. <code>ai-hooks config claude</code> prints this with your binary path.</p>
{code('''{
  "hooks": {
    "PreToolUse":  [{"matcher": "Bash", "hooks": [{"type": "command", "command": "ai-hooks hook claude", "timeout": 10}]}],
    "PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "ai-hooks hook claude", "timeout": 10}]}]
  }
}''')}
<h2>A Claude Code PreToolUse hook example</h2>
<p>The hook reads the payload on standard input and, for a risky command, answers with <code>permissionDecision: deny</code> and a reason. The model reads the reason and re-runs the command through the redactor.</p>
{code('''echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"journalctl -u app"}}' | ai-hooks hook claude
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"ai-hooks [journalctl-unit]: ..."}}''')}
<h2>PostToolUse: mask what the model sees</h2>
<p>For <code>PostToolUse</code> the hook walks every string in <code>tool_response</code> and, if anything was redacted, returns the same object as <code>updatedToolOutput</code>. When nothing was redacted it prints nothing and costs about 11 ms.</p>
<h2>As a plugin</h2>
<p>The repository is also a one-plugin marketplace: <code>claude plugin marketplace add koalabs-ai/ai-hooks</code>, then <code>claude plugin install ai-hooks@ai-hooks</code>. The binary must be on your <code>PATH</code>.</p>
<p>See also: <a href="numbers.html">numbers</a>, <a href="faq.html">FAQ</a>.</p>""")

page("kimi-code.html", "ai-hooks for Kimi Code: block commands that print secrets",
     "Guard Kimi Code from running commands that print secrets with an ai-hooks PreToolUse hook. Verified on Kimi Code 2.6.1; output redaction is not possible in Kimi hooks.",
     f"""<p><strong>Status: verified</strong> on Kimi Code 2.6.1 in a real session (guard only). Kimi hooks can block a tool call but cannot rewrite its output, so the redaction half is not available there; use <code>ai-hooks exec</code> or a pipe.</p>
<h2>Setup</h2>
<p>Add to <code>~/.kimi-code/config.toml</code> (<code>ai-hooks config kimi</code> prints it):</p>
{code('''[[hooks]]
event = "PreToolUse"
matcher = "Bash"
command = "ai-hooks hook kimi"
timeout = 10''')}
<p>When Kimi tries <code>journalctl -u app</code> the tool result it gets back is the ai-hooks reason, and it quoted it to the user in the verification run. Kimi reads hooks only from the user-level config, never from a project.</p>
<p>See also: <a href="any-shell.html">any shell</a>.</p>""")

page("codex-cli.html", "ai-hooks for Codex CLI (untested)",
     "Using ai-hooks with OpenAI Codex CLI: status, what the vendor documents, and the pipe-mode fallback that works today.",
     f"""{HARNESS_NOTE_UNTESTED}
<h2>What the vendor documents</h2>
<p>Codex CLI documents <code>PreToolUse</code> and <code>PostToolUse</code> command hooks for its shell tool (a <code>hooks.json</code> or a <code>[hooks]</code> table in <code>config.toml</code>, version 0.124 or newer, at the time of writing). The payload looks like Claude Code's. <code>ai-hooks install codex</code> writes the <code>PreToolUse</code> hook (and <code>ai-hooks hook codex</code> answers it); output rewriting would use a <code>block</code> decision that replaces the result with the redacted text. Written from the documentation; not run, because Codex is not installed on the machine this was built on.</p>
<h2>What works today</h2>
{code('''ai-hooks guard -- 'journalctl -u app'        # exit 2 with the reason on stderr
some-command 2>&1 | ai-hooks redact
ai-hooks exec -- some-command''')}
<p>Run the agent's shell commands through <code>ai-hooks exec</code> (for example with a shell wrapper or an instruction in <code>AGENTS.md</code>) to get both halves with any harness.</p>""")

page("opencode.html", "ai-hooks for opencode: block commands that print secrets",
     "Guard opencode from printing secrets: an ai-hooks plugin blocks risky shell commands and redacts tool output. Verified on opencode 2.2.7.",
     f"""<p><strong>Status: verified</strong> on opencode 2.2.7 in a real session: <code>docker inspect web</code> was refused with the ai-hooks message, and a shell command that printed a fake AWS key came back redacted.</p>
<h2>Setup</h2>
{code("ai-hooks install opencode            # writes ~/.config/opencode/plugins/ai-hooks.js\nai-hooks install opencode --project   # or .opencode/plugins/ai-hooks.js in this project\nai-hooks uninstall opencode")}
<p>The plugin uses opencode's server plugin API: a <code>tool.execute.before</code> hook that throws to block, and a <code>tool.execute.after</code> hook that rewrites the result. It starts the binary with arguments (no shell). The shell tool is named <code>shell</code> in opencode 2.x and <code>bash</code> in 1.x; the plugin handles both.</p>
<p>See also: <a href="mcp.html">MCP</a>, <a href="any-shell.html">any shell</a>.</p>""")

page("mcp.html", "ai-hooks as an MCP server: guard, redact, scan and safe_run tools",
     "Use ai-hooks from any MCP-capable coding agent without hooks: tools to check a command, redact text, scan for secrets and run a command with redacted output.",
     f"""<p><strong>Status: verified</strong> with Claude Code's MCP client: the <code>redact</code>, <code>guard</code> and <code>safe_run</code> tools were called by a real session and their results read back.</p>
<h2>Register the server</h2>
{code("claude mcp add ai-hooks -- ai-hooks mcp          # Claude Code\n# any other MCP client: command ai-hooks, args [mcp], transport stdio")}
<h2>Tools</h2>
<ul><li><code>guard</code>: is this command safe to run? Returns blocked, the rule and a one-line instruction.</li>
<li><code>redact</code>: mask secret-shaped strings in text; returns the redacted text and counts by type.</li>
<li><code>scan</code>: list secret-shaped values in text (type, fingerprint, line; never the values).</li>
<li><code>safe_run</code>: run a command after the guard allows it, with its output redacted, time-limited and size-capped.</li></ul>
<p><code>safe_run</code> runs commands as the user who started the server: it is not a sandbox. Turn it off with <code>ai-hooks mcp --no-run</code> or restrict it with <code>--allow-run REGEX</code> (commands with shell metacharacters are then refused). Works for Cline, Continue, Amp, Zed and other MCP clients; they are not tested here.</p>""")

page("cursor.html", "ai-hooks for Cursor (untested)",
     "Using ai-hooks with Cursor: status, the shell hooks the vendor documents, and the pipe-mode fallback that works today.",
     f"""{HARNESS_NOTE_UNTESTED}
<h2>What the vendor documents</h2>
<p>Cursor documents <code>beforeShellExecution</code> (can allow or deny) and <code>afterShellExecution</code> (observe only), configured in <code>hooks.json</code>. <code>ai-hooks install cursor</code> writes the guard half; output redaction is not possible in Cursor's hooks. Written from the documentation; not run.</p>
<h2>What works today</h2>
{code('''ai-hooks guard -- 'cat .env'; echo $?     # 2
ai-hooks exec -- some-command''')}""")

page("any-shell.html", "ai-hooks for any shell: redact secrets from terminal output",
     "Redact secrets from terminal output with a pipe, guard a command before it runs, or wrap it with ai-hooks exec. Works with any agent that runs shell commands.",
     f"""<p><strong>Status: verified.</strong> This is the mode the tests and the demo use.</p>
<h2>Redact secrets from terminal output</h2>
{code('''kubectl logs deploy/api 2>&1 | ai-hooks redact
docker compose logs | ai-hooks redact --stream
some-cmd | ai-hooks redact --json > /dev/null     # {"redacted":2,"by_type":{...}}: counts only''')}
<h2>Guard, then run, then redact</h2>
{code('''ai-hooks guard -- 'cat .env'        # exit 2, one line on stderr
ai-hooks exec -- cat .env           # guard, run, redact the output, keep the exit code''')}
<h2>Your own rules</h2>
<p>Add rules, disable defaults or allow patterns in <code>~/.config/ai-hooks/rules.json</code>. <code>ai-hooks rules</code> prints the defaults. See the <a href="{REPO}/blob/main/docs/DESIGN.md">design note</a>.</p>""")

page("numbers.html", "ai-hooks numbers: detection, false alarms, latency",
     "Measured detection and false-alarm rates on the bundled fake corpus, cold-start latency and binary size, with the machine and the method.",
     f"""<p>Measured on one machine: Intel Core Ultra 7 155H, 22 threads, Linux 7.2, Go 1.27.4, while it was busy with other work (load average 7 to 12). Read them as conservative. Reproduce with <code>make selftest</code> and <code>make latency</code>. The per-type table is in <code>docs/DETECTION.md</code>.</p>
<table>
<tr><th>Measure</th><th>Result</th></tr>
<tr><td>Detection, bundled corpus</td><td>123/123 fake secrets redacted, across 113 detector types</td></tr>
<tr><td>False alarms, bundled corpus</td><td>0/43 clean samples touched</td></tr>
<tr><td>Known misses</td><td>5: a bare <code>TOKEN=value</code>, a base64-encoded key, a key split by spaces, a password in prose, a value under the minimum length</td></tr>
<tr><td>Known false alarms</td><td>2: <code>md5sum</code> output (bare 32-hex), <code>password = getpass.getpass(...)</code> in code</td></tr>
<tr><td>Binary size</td><td>3.9 MB, linux/amd64, stripped, static, no dependencies</td></tr>
<tr><td>Cold start, hook, allowed command</td><td>5.2 ms mean, 6.1 ms p95 (150 launches) with the machine lightly loaded, against 4.0 ms for a bare process start; at load average 12: 13.7 ms against 13.0 ms. The tool adds roughly 1 to 6 ms to the cost of starting a process.</td></tr>
<tr><td>Throughput</td><td><code>redact</code> on a 10 MB log with a few secrets: 9 to 12 s of CPU at load average 17 (about 1 MB/s). Built for command output, not log archives.</td></tr>
<tr><td>Cold start, redact, small text</td><td>about 10 ms; the Python original it descends from: 91 ms</td></tr>
<tr><td>Output vs the original shape detectors</td><td>byte-identical in compatibility mode (<code>AI_HOOKS_PARITY=1</code>) on 20,000 synthetic texts and thousands of real text files; see PARITY.md in the repository</td></tr>
</table>
<p>The corpus is small and written by the authors. It shows the tool does what it says on known shapes, not how it will do on your data. False-alarm reports with a fake example are the most useful contribution.</p>""")

faq_html = "".join(f"<h2>{e(q)}</h2><p>{e(a)}</p>" for q, a in FAQ)
page("faq.html", "ai-hooks FAQ: secrets, AI agents, transcripts, redaction",
     "Answers about stopping AI coding agents from leaking secrets: Claude Code hooks, redacting terminal output, what to do after a leak, limits.",
     faq_html, h1="Frequently asked questions")

# ---- rendering
CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1c2130;--dim:#5a6376;--line:#dde1ea;--code:#f2f4f8;--accent:#c2303c}
@media (prefers-color-scheme:dark){:root{--bg:#14161b;--fg:#d9dde6;--dim:#8a93a6;--line:#2a2e38;--code:#1c1f27;--accent:#ff6b6b}}
body{margin:0;background:var(--bg);color:var(--fg);font:17px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header,main,footer{max-width:900px;margin:0 auto;padding:0 20px}
nav{display:flex;flex-wrap:wrap;gap:6px 16px;padding:16px 0;border-bottom:1px solid var(--line)}
nav a{color:var(--dim);text-decoration:none}nav a[aria-current]{color:var(--fg);font-weight:600}
h1{font-size:2.2rem;margin:1.2em 0 .3em}h2{margin:1.6em 0 .4em;font-size:1.3rem}
.lead{font-size:1.15rem;color:var(--dim)}
pre{background:var(--code);padding:14px;border-radius:8px;overflow:auto;font-size:.9rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}
img{max-width:100%;height:auto;border-radius:8px}a{color:var(--accent)}
.warn{border-left:4px solid var(--accent);padding:4px 14px;background:var(--code)}
footer{color:var(--dim);font-size:.9rem;padding:30px 20px 50px;border-top:1px solid var(--line);margin-top:40px}
"""

def render(slug, p):
    url = f"{BASE}/" if slug == "index.html" else f"{BASE}/{slug}"
    nav = "".join(f'<a href="{h}"' + (' aria-current="page"' if h == slug else "") + f">{l}</a>" for h, l in NAV)
    lds = list(p["ld"])
    if slug == "index.html":
        lds.append({"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "ai-hooks",
                    "applicationCategory": "DeveloperApplication", "operatingSystem": "Linux, macOS",
                    "description": DESC, "url": f"{BASE}/", "license": "https://www.apache.org/licenses/LICENSE-2.0",
                    "codeRepository": REPO, "programmingLanguage": "Go", "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
                    "image": f"{BASE}/assets/social-preview.png"})
    if slug == "faq.html":
        lds.append({"@context": "https://schema.org", "@type": "FAQPage",
                    "mainEntity": [{"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}} for q, a in FAQ]})
    ld = "".join(f'<script type="application/ld+json">{json.dumps(x, ensure_ascii=False)}</script>\n' for x in lds)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(p['title'])}</title>
<meta name="description" content="{e(p['desc'])}">
<link rel="canonical" href="{url}">
<meta property="og:type" content="website"><meta property="og:site_name" content="ai-hooks">
<meta property="og:title" content="{e(p['title'])}"><meta property="og:description" content="{e(p['desc'])}">
<meta property="og:url" content="{url}"><meta property="og:image" content="{BASE}/assets/social-preview.png">
<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="{e(p['title'])}">
<meta name="twitter:description" content="{e(p['desc'])}"><meta name="twitter:image" content="{BASE}/assets/social-preview.png">
<link rel="stylesheet" href="assets/style.css">
{ld}</head><body>
<header><nav aria-label="Main">{nav}</nav></header>
<main><h1>{e(p['h1'])}</h1>
{p['body']}
</main>
<footer>ai-hooks is Apache-2.0. <a href="{REPO}">Source</a> · Built and used daily at <a href="https://koalabs.ai">KOA Labs</a>.</footer>
</body></html>
"""

def main():
    (HERE / "assets").mkdir(exist_ok=True)
    (HERE / "assets" / "style.css").write_text(CSS.strip() + "\n")
    demo = HERE.parent / "demo" / "out"
    for g in ("ai-hooks-demo-dark.gif", "ai-hooks-demo-light.gif"):
        if (demo / g).exists():
            shutil.copy(demo / g, HERE / "assets" / g)
    for slug, p in PAGES.items():
        (HERE / slug).write_text(render(slug, p))
    urls = [f"{BASE}/" if s == "index.html" else f"{BASE}/{s}" for s in PAGES]
    sm = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    sm += [f"  <url><loc>{u}</loc><lastmod>{DATE}</lastmod></url>" for u in urls] + ["</urlset>"]
    (HERE / "sitemap.xml").write_text("\n".join(sm) + "\n")
    bots = ["GPTBot", "OAI-SearchBot", "ChatGPT-User", "ClaudeBot", "Claude-User", "Claude-SearchBot", "anthropic-ai",
            "PerplexityBot", "Perplexity-User", "Google-Extended", "Applebot-Extended", "CCBot", "Bingbot", "Googlebot"]
    robots = "\n".join(f"User-agent: {b}\nAllow: /\n" for b in bots) + f"\nUser-agent: *\nAllow: /\n\nSitemap: {BASE}/sitemap.xml\n"
    (HERE / "robots.txt").write_text(robots)
    llms = f"""# ai-hooks

> {DESC}

Status: pre-release, not yet published. Everything below describes what exists in the repository today.

What it does:
- `ai-hooks guard`: decides before a shell command runs whether it is likely to print secrets (reading .env files, journalctl -u, docker inspect, printenv, curl -v with a token...). Exit 0 allow, 2 block, with a one-line instruction.
- `ai-hooks redact`: filter from stdin to stdout replacing secret-shaped strings with <REDACTED:type:fingerprint>. About 40 detectors. `--json` reports counts by type, never values.
- `ai-hooks hook claude|kimi`: hook entry points. Verified in live sessions: Claude Code (guard and output redaction), Kimi Code (guard only).
- `ai-hooks exec -- cmd`: guard, run, redact, keep the exit code.

What it is not: a secret manager, a repository scanner (use gitleaks, trufflehog or detect-secrets for that), or a guarantee. Detection is by shape; known misses are listed on the numbers page. It does not stop an agent that deliberately encodes its output.

Not tested: Codex CLI, opencode, Cursor, Gemini CLI and other harnesses (their vendors document hooks; no support is claimed).

## Docs
- [Home]({BASE}/): overview and demo
- [Claude Code]({BASE}/claude-code.html)
- [Kimi Code]({BASE}/kimi-code.html)
- [Any shell]({BASE}/any-shell.html)
- [Numbers]({BASE}/numbers.html): measured on one machine, with method
- [FAQ]({BASE}/faq.html)
- [Source and design note]({REPO})

License: Apache-2.0.
"""
    (HERE / "llms.txt").write_text(llms)
    key = "27c492dfe6535de2c1f9178f62c4d457"
    (HERE / f"{key}.txt").write_text(key + chr(10))  # IndexNow key file (public by design)
    print("pages:", len(PAGES))

main()
