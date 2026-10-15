"""Record the step-by-step tdcc-exact run for real, then render it as a terminal video.

Usage: python tools/record_demo.py <workdir> <out.mp4>

Needs Pillow, ffmpeg, tdcc-exact on PATH (pip install -e .) and the DejaVu fonts (found in the
usual system font folders, or in $TDCC_DEMO_FONTS).
Each command is really executed; output lines are shown at the times they were printed.
Typing of commands and the '#' narration lines are paced for a viewer.
"""
import os
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

if len(sys.argv) != 3:
    sys.exit(__doc__.split("\n\n")[1])
for tool in ("ffmpeg", "tdcc-exact"):           # before spending a recording on it
    if shutil.which(tool) is None:
        sys.exit(f"record_demo: {tool} is not on PATH")
WORK, OUT = sys.argv[1], sys.argv[2]
os.makedirs(WORK, exist_ok=True)

FONT_DIRS = [os.environ.get("TDCC_DEMO_FONTS", ""), "/usr/share/fonts/truetype/dejavu",
             "/usr/share/fonts/dejavu", "/usr/share/fonts/TTF", "/usr/local/share/fonts",
             str(Path.home() / "Library/Fonts"), "/Library/Fonts"]


def font(name: str, size: int):
    for d in filter(None, FONT_DIRS):
        if (Path(d) / name).exists():
            return ImageFont.truetype(str(Path(d) / name), size)
    sys.exit(f"record_demo: {name} not found; install the DejaVu fonts or set TDCC_DEMO_FONTS")


MONO = font("DejaVuSansMono.ttf", 25)               # (checked before the recording, too)
MONO_B = font("DejaVuSansMono-Bold.ttf", 25)
SANS_B = font("DejaVuSans-Bold.ttf", 24)

STEPS = [
    ("renter opens a yes/no oracle job", 'tdcc-exact job new --model tiny --question "Will it rain tomorrow?" --id j1 --out job.json'),
    ("provider A runs it honestly (on the chip's simulator)", "tdcc-exact run --job job.json --provider A --out a.json --trace a.trace.json"),
    ("provider B cheats: skips layer 1 to save compute", "tdcc-exact run --job job.json --provider B --skip-layer 1 --out b.json --trace b.trace.json"),
    ("a verifier re-runs A on a laptop", "tdcc-exact verify --job job.json --receipt a.json"),
    ("...and B", "tdcc-exact verify --job job.json --receipt b.json"),
    ("find the first instruction B got wrong", "tdcc-exact dispute --job job.json --trace b.trace.json --receipt b.json --replay-skip-layer 1"),
]

# ---------- record
env = dict(os.environ, PYTHONUNBUFFERED="1")
recorded = []  # (comment, cmd, [(dt, line)], exit)
for comment, cmd in STEPS:
    t0 = time.monotonic()
    p = subprocess.Popen(cmd, shell=True, cwd=WORK, env=env, text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lines = [(time.monotonic() - t0, ln.rstrip("\n")) for ln in p.stdout]
    p.wait()
    recorded.append((comment, cmd, lines, p.returncode, time.monotonic() - t0))
    print(f"$ {cmd}  [exit {p.returncode}, {time.monotonic() - t0:.2f}s]")
    for _, ln in lines:
        print("  " + ln)

# ---------- timeline of terminal events: (time, kind, text)
TYPE_CPS = 55          # typing speed for commands
PAUSE = 0.35
events, t = [], 0.6
for comment, cmd, lines, code, dur in recorded:
    events.append((t, "comment", "# " + comment))
    t += 0.55
    events.append((t, "cmd", "$ " + cmd))
    t += len(cmd) / TYPE_CPS + 0.25        # typed, then Enter
    start = t
    for dt, ln in lines:
        events.append((start + dt, "out", ln))
    t = start + dur + PAUSE
    if code:
        events.append((t - PAUSE + 0.01, "exit", f"[exit {code}]"))
END = t + 2.5

# ---------- render
W, H, FPS = 1920, 1080, 30
BG, BAR, FG, DIM = (0x26, 0x21, 0x1D), (0x3A, 0x33, 0x2D), (0xF7, 0xF1, 0xEA), (0xA8, 0x9C, 0x90)
GREEN, RED, AMBER, CYAN, PURPLE = (120, 205, 140), (240, 105, 95), (232, 184, 96), (110, 200, 255), (0xE2, 0xC0, 0x94)
LH, X0, Y0 = 34, 40, 90
COLS = int((W - 2 * X0) / MONO.getlength("m"))
ROWS = (H - Y0 - 30) // LH


def color_of(kind, text):
    if kind == "comment":
        return PURPLE, MONO_B
    if kind == "cmd":
        return (0xC8, 0x95, 0x5E), MONO_B
    if kind == "exit":
        return DIM, MONO
    if "ACCEPT" in text:
        return GREEN, MONO_B
    if "CHALLENGE" in text or "first fault" in text:
        return RED, MONO_B
    if text.startswith("B: YES"):
        return AMBER, MONO
    return FG, MONO


def screen_lines(now):
    rows = []
    for et, kind, text in events:
        if et > now:
            break
        if kind == "cmd":
            n = min(len(text), 2 + int((now - et) * TYPE_CPS))
            text = text[:n]
        col, font = color_of(kind, text)
        for part in textwrap.wrap(text, COLS, subsequent_indent="    ", break_long_words=True) or [""]:
            rows.append((part, col, font))
    return rows[-ROWS:]


ff = subprocess.Popen(["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24",
                       "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-", "-c:v", "libx264",
                       "-pix_fmt", "yuv420p", "-crf", "18", "-movflags", "+faststart", OUT],
                      stdin=subprocess.PIPE)
for k in range(int(END * FPS)):
    now = k / FPS
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 56], fill=BAR)
    for i, c in enumerate([(0x6B,0x5E,0x52)]*3):
        d.ellipse([22 + i * 32, 18, 42 + i * 32, 38], fill=c)
    title = "TDCC Exact  \u00b7  verifiable AI chip  \u00b7  bit-exact chip simulator on a laptop"
    d.text(((W - d.textlength(title, font=SANS_B)) / 2, 14), title, font=SANS_B, fill=DIM)
    rows = screen_lines(now)
    for i, (text, col, font) in enumerate(rows):
        d.text((X0, Y0 + i * LH), text, font=font, fill=col)
    if (k // 15) % 2 == 0 and rows:  # blinking cursor after the last row
        x = X0 + font.getlength(rows[-1][0]) + 4
        y = Y0 + (len(rows) - 1) * LH
        d.rectangle([x, y + 4, x + 13, y + 28], fill=FG)
    ff.stdin.write(img.tobytes())
ff.stdin.close()
if ff.wait() != 0:
    sys.exit(f"record_demo: ffmpeg failed (exit {ff.returncode}); {OUT} is not a video")
print(f"video: {OUT}  {END:.1f}s")
