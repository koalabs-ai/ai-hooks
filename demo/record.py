#!/usr/bin/env python3
"""Reproducible demo: runs the real binary on FAKE data in a temp directory and
renders what a terminal would show, as PNG frames, a GIF and per-scene stills.

    python3 demo/record.py --bin dist/ai-hooks --out demo/out

Needs Pillow and ffmpeg. Nothing here touches your home directory: the commands
run in a throw-away directory with HOME pointed at it, and the prompt is
fixed to john@laptop.
"""
import argparse, json, os, re, shutil, subprocess, tempfile, textwrap
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

COLS, ROWS = 92, 11
FONT_PT = 19
FONT_PATHS = [
    "/usr/share/fonts/TTF/JetBrainsMono-Regular.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
]
BOLD_PATHS = [p.replace("Regular", "Bold").replace("DejaVuSansMono.ttf", "DejaVuSansMono-Bold.ttf") for p in FONT_PATHS]
FPS = 10

THEMES = {
    "dark": dict(bg=(22, 24, 29), fg=(214, 218, 226), dim=(122, 130, 145), green=(126, 214, 142),
                 blue=(122, 176, 255), red=(255, 107, 107), hl_bg=(120, 38, 48), hl_fg=(255, 226, 226),
                 yellow=(244, 200, 108), bar=(34, 37, 44), dots=[(255, 95, 86), (255, 189, 46), (39, 201, 63)]),
    "light": dict(bg=(250, 250, 252), fg=(36, 41, 51), dim=(120, 128, 142), green=(24, 128, 56),
                  blue=(30, 90, 190), red=(190, 40, 50), hl_bg=(255, 220, 224), hl_fg=(140, 20, 34),
                  yellow=(150, 100, 0), bar=(234, 236, 240), dots=[(255, 95, 86), (255, 189, 46), (39, 201, 63)]),
}


def load_font(paths, size):
    for p in paths:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    raise SystemExit("no monospace font found")


FONT = load_font(FONT_PATHS, FONT_PT)
FONT_B = load_font(BOLD_PATHS + FONT_PATHS, FONT_PT)
CW = FONT.getlength("M")
LH = FONT_PT + 9
PAD = 26
BAR = 40
W = int(COLS * CW) + 2 * PAD
H = ROWS * LH + 2 * PAD + BAR

PROMPT_USER, PROMPT_PATH = "john@laptop", "~/app"
FAKE_ENV = """user=john
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
HOOK_PAYLOAD = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                           "tool_input": {"command": "journalctl -u app -n 50"}})

# (title, [steps]); a step is ("comment", text) or ("cmd", shown_command, real_shell_command)
SCENES = [
    ("1-the-leak", [
        ("comment", "# 1. an agent runs cat .env: your keys are now in the transcript"),
        ("cmd", "cat .env", "cat .env"),
    ]),
    ("2-redacted", [
        ("comment", "# 2. through ai-hooks: secrets gone, the rest untouched"),
        ("cmd", "cat .env | ai-hooks redact", "cat .env | ai-hooks redact"),
    ]),
    ("3-guard", [
        ("comment", "# 3. the guard stops a risky command before it runs"),
        ("cmd", "ai-hooks guard -- 'journalctl -u app'", "ai-hooks guard -- 'journalctl -u app'; echo \"exit $?\""),
        ("cmd", "ai-hooks guard -- 'journalctl -u app | ai-hooks redact' && echo allowed",
         "ai-hooks guard -- 'journalctl -u app | ai-hooks redact' && echo allowed"),
    ]),
    ("4-numbers", [
        ("comment", "# 4. the bundled corpus (fake secrets only) gives the numbers"),
        ("cmd", "ai-hooks test --short", "ai-hooks test --short"),
    ]),
    ("5-latency", [
        ("comment", "# 5. it runs on every command, so it has to be fast"),
        ("cmd", "time ai-hooks redact < .env > /dev/null", "time ai-hooks redact < .env > /dev/null"),
        ("cmd", "time ai-hooks hook claude < payload.json > /dev/null", "time ai-hooks hook claude < payload.json > /dev/null"),
    ]),
]


def run_real(binary, workdir):
    """Run every command for real; return {real_cmd: output text}."""
    home = Path(workdir) / "home"
    app = Path(workdir) / "app"
    home.mkdir(); app.mkdir()
    (app / ".env").write_text(FAKE_ENV)
    (app / "payload.json").write_text(HOOK_PAYLOAD)
    bindir = Path(workdir) / "bin"; bindir.mkdir()
    shutil.copy(binary, bindir / "ai-hooks")
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(home), "TIMEFORMAT": "real %3Rs",
           "AI_HOOKS_RULES": str(home / "none.json"), "AI_HOOKS_LOG": str(home / "log"),
           "XDG_CONFIG_HOME": str(home / ".config"), "LANG": "C.UTF-8"}
    outs = {}
    for _, steps in SCENES:
        for s in steps:
            if s[0] != "cmd":
                continue
            real = s[2]
            # warm the file cache once, then measure what the viewer will see
            wrapped = "{ " + real + "\n} 2>&1"
            subprocess.run(["bash", "-c", wrapped], cwd=app, env=env, capture_output=True)
            r = subprocess.run(["bash", "-c", wrapped], cwd=app, env=env, capture_output=True, text=True)
            outs[real] = r.stdout.rstrip("\n")
    return outs


class Term:
    """A tiny screen: list of rows, each a list of (text, kind)."""

    def __init__(self):
        self.rows = []
        self.typing = None  # (prefix_segments, partial_text)

    def clear(self):
        self.rows = []

    def add(self, segs):
        self.rows.append(segs)


def wrap_out(line):
    return textwrap.wrap(line, COLS - 2, drop_whitespace=False, break_long_words=True, break_on_hyphens=False, replace_whitespace=False) or [""]


def colorize(line):
    """Split an output line into (text, kind) segments."""
    segs, pos = [], 0
    for m in re.finditer(r"<REDACTED:[^>]*>|ai-hooks \[[^\]]+\]:|\b0/\d+\b|\b\d+/\d+ (?:secrets|clean)|\bblocked\b|^allowed$|^exit 2$|real \d+\.\d+s", line):
        if m.start() > pos:
            segs.append((line[pos:m.start()], "fg"))
        t = m.group(0)
        kind = "hl" if t.startswith("<REDACTED") else "red" if t.startswith("ai-hooks [") or t == "exit 2" else "green"
        segs.append((t, kind))
        pos = m.end()
    if pos < len(line):
        segs.append((line[pos:], "fg"))
    return segs


def draw(term, theme, typing=None, cursor=True, label=None):
    t = THEMES[theme]
    img = Image.new("RGB", (W, H), t["bg"])
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, BAR], fill=t["bar"])
    for i, c in enumerate(t["dots"]):
        d.ellipse([PAD + i * 26, 13, PAD + i * 26 + 14, 27], fill=c)
    title = "john@laptop: ~/app"
    d.text((W // 2 - FONT.getlength(title) / 2, 9), title, font=FONT, fill=t["dim"])
    colors = {"fg": t["fg"], "dim": t["dim"], "green": t["green"], "blue": t["blue"], "red": t["red"], "yellow": t["yellow"]}
    rows = list(term.rows)
    if typing is not None:
        rows.append(typing)
    rows = rows[-ROWS:]
    y = BAR + PAD
    for segs in rows:
        x = PAD
        for text, kind in segs:
            w = FONT.getlength(text)
            if kind == "hl":
                d.rounded_rectangle([x - 1, y - 1, x + w + 1, y + LH - 5], radius=4, fill=t["hl_bg"])
                d.text((x, y), text, font=FONT_B, fill=t["hl_fg"])
            else:
                d.text((x, y), text, font=FONT_B if kind in ("red", "green") else FONT, fill=colors.get(kind, t["fg"]))
            x += w
        y += LH
    if cursor and typing is not None:
        x = PAD + sum(FONT.getlength(s[0]) for s in typing)
        yy = BAR + PAD + (len(rows) - 1) * LH
        d.rectangle([x, yy + 2, x + CW - 2, yy + LH - 5], fill=t["fg"])
    return img


def prompt_segs():
    return [(PROMPT_USER, "green"), (":", "fg"), (PROMPT_PATH, "blue"), ("$ ", "fg")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="dist/ai-hooks")
    ap.add_argument("--out", default="demo/out")
    ap.add_argument("--themes", default="dark,light")
    a = ap.parse_args()
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    work = tempfile.mkdtemp(prefix="ai-hooks-demo-")
    try:
        outs = run_real(os.path.abspath(a.bin), work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    (out / "transcript.json").write_text(json.dumps({"fake_env": FAKE_ENV, "outputs": outs}, indent=1))

    for theme in a.themes.split(","):
        frames = Path(tempfile.mkdtemp(prefix=f"frames-{theme}-"))
        n = 0

        def emit(img, hold=1):
            nonlocal n
            for _ in range(hold):
                img.save(frames / f"f{n:05d}.png"); n += 1

        for name, steps in SCENES:
            term = Term()
            emit(draw(term, theme, typing=prompt_segs(), cursor=True), 2)
            for s in steps:
                if s[0] == "comment":
                    txt = s[1]
                    for i in range(0, len(txt) + 1, 7):
                        emit(draw(term, theme, typing=prompt_segs() + [(txt[:i], "dim")]))
                    term.add(prompt_segs() + [(txt, "dim")])
                    emit(draw(term, theme, typing=prompt_segs()), 3)
                    continue
                shown, real = s[1], s[2]
                for i in range(0, len(shown) + 1, 3):
                    emit(draw(term, theme, typing=prompt_segs() + [(shown[:i], "fg")]))
                emit(draw(term, theme, typing=prompt_segs() + [(shown, "fg")]), 3)
                term.add(prompt_segs() + [(shown, "fg")])
                for line in outs[real].split("\n"):
                    for piece in wrap_out(line):
                        term.add([("  ", "fg")] + colorize(piece))
                    emit(draw(term, theme, typing=None), 1)
                emit(draw(term, theme, typing=prompt_segs()), 5)
            emit(draw(term, theme, typing=prompt_segs()), 6)
            last = frames / f"f{n-1:05d}.png"
            shutil.copy(last, out / f"{name}-{theme}.png")
        gif = out / f"ai-hooks-demo-{theme}.gif"
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(FPS), "-i", str(frames / "f%05d.png"),
                        "-vf", "scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=none",
                        str(gif)], check=True)
        print(f"{theme}: {n} frames, {n / FPS:.1f}s, {gif.stat().st_size // 1024} KiB")
        shutil.rmtree(frames, ignore_errors=True)


if __name__ == "__main__":
    main()
