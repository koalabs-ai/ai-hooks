#!/usr/bin/env python3
"""Render the 1280x640 social preview (GitHub repo card, Open Graph, Twitter card).
Uses the real redactor output for the example, so the image never drifts from the tool.

    python3 demo/social.py --bin dist/ai-hooks --out site/assets/social-preview.png
"""
import argparse, subprocess
from PIL import Image, ImageDraw, ImageFont

F = "/usr/share/fonts/TTF/JetBrainsMono-Regular.ttf"
FB = "/usr/share/fonts/TTF/JetBrainsMono-Bold.ttf"
ap = argparse.ArgumentParser()
ap.add_argument("--bin", default="dist/ai-hooks")
ap.add_argument("--out", default="site/assets/social-preview.png")
a = ap.parse_args()

before = ["user=john", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"]
after = subprocess.run([a.bin, "redact"], input="\n".join(before) + "\n", capture_output=True, text=True).stdout.splitlines()

W, H = 1280, 640
img = Image.new("RGB", (W, H), (16, 18, 23))
d = ImageDraw.Draw(img)
f = lambda p, s: ImageFont.truetype(p, s)
d.rectangle([0, 0, 12, H], fill=(255, 107, 107))
d.text((70, 40), "ai-hooks", font=f(FB, 110), fill=(240, 243, 248))
d.text((72, 180), "Stop AI coding agents from", font=f(FB, 44), fill=(214, 218, 226))
d.text((72, 236), "leaking secrets into transcripts.", font=f(FB, 44), fill=(214, 218, 226))
d.text((72, 306), "A fast guard + redactor for Claude Code, Kimi and any shell.", font=f(F, 26), fill=(122, 130, 145))

def panel(y, title, lines, hl):
    d.rounded_rectangle([72, y, 1208, y + 96 + (len(lines) - 1) * 0], radius=12, fill=(30, 33, 40))
    d.text((92, y + 10), title, font=f(F, 18), fill=(122, 130, 145))
    for i, ln in enumerate(lines):
        x, yy = 92, y + 36 + i * 28
        if hl and "<REDACTED" in ln:
            pre, rest = ln.split("<REDACTED", 1)
            tok = "<REDACTED" + rest
            d.text((x, yy), pre, font=f(F, 22), fill=(214, 218, 226))
            xw = x + d.textlength(pre, font=f(F, 22))
            tw = d.textlength(tok, font=f(FB, 22))
            d.rounded_rectangle([xw - 2, yy - 2, xw + tw + 2, yy + 28], radius=5, fill=(120, 38, 48))
            d.text((xw, yy), tok, font=f(FB, 22), fill=(255, 226, 226))
        else:
            d.text((x, yy), ln, font=f(F, 22), fill=(214, 218, 226))

panel(385, "$ cat .env", before, False)
panel(493, "$ cat .env | ai-hooks redact", after, True)
d.text((W - 72 - d.textlength("Apache-2.0  |  one static binary", font=f(F, 20)), 603), "Apache-2.0  |  one static binary", font=f(F, 20), fill=(122, 130, 145))
img.save(a.out)
print("wrote", a.out)
