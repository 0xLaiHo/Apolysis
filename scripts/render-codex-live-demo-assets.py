#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


REPO_ROOT = Path(__file__).resolve().parents[1]
ASSET_DIR = REPO_ROOT / "docs" / "assets" / "codex-live-demo"
TRANSCRIPT = ASSET_DIR / "terminal-transcript.txt"
SUMMARY = ASSET_DIR / "summary.json"
CAST = ASSET_DIR / "codex-live-demo.cast"
GIF = ASSET_DIR / "codex-live-demo.gif"

CAST_TIMESTAMP = 1783036800
CAST_WIDTH = 104
CAST_HEIGHT = 24
GIF_WIDTH = 1080
GIF_HEIGHT = 640


def load_public_transcript() -> list[str]:
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    if summary.get("demo_status") != "validated_local_live":
        raise SystemExit("summary.json is not marked validated_local_live")
    if summary.get("redaction_boundary") != "curated_public_excerpt":
        raise SystemExit("summary.json is not marked as a curated public excerpt")

    text = TRANSCRIPT.read_text(encoding="utf-8").strip("\n")
    return text.splitlines()


def render_cast(lines: list[str]) -> None:
    header = {
        "version": 2,
        "width": CAST_WIDTH,
        "height": CAST_HEIGHT,
        "timestamp": CAST_TIMESTAMP,
        "env": {"TERM": "xterm-256color", "SHELL": "bash"},
        "title": "Apolysis Codex live demo",
    }
    events: list[str] = [json.dumps(header, sort_keys=True)]
    elapsed = 0.0
    for line in lines:
        elapsed += 0.25 if line.startswith("$ ") else 0.55
        events.append(json.dumps([round(elapsed, 2), "o", f"{line}\r\n"]))
    CAST.write_text("\n".join(events) + "\n", encoding="utf-8")


def load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu-sans-mono-fonts/DejaVuSansMono.ttf",
    ]
    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return ImageFont.truetype(str(path), size=size)
    return ImageFont.load_default()


def wrap_lines(lines: list[str]) -> list[str]:
    wrapped: list[str] = []
    for line in lines:
        if not line:
            wrapped.append("")
            continue
        wrapped.extend(
            textwrap.wrap(
                line,
                width=92,
                break_long_words=False,
                break_on_hyphens=False,
                subsequent_indent="  ",
            )
            or [""]
        )
    return wrapped


def line_color(line: str) -> tuple[int, int, int]:
    if line.startswith("$ "):
        return (105, 214, 255)
    if "missing_intent" in line:
        return (255, 122, 118)
    if "intent_correlation" in line or "process_executable" in line:
        return (122, 232, 167)
    if "passed" in line or "completed successfully" in line:
        return (185, 242, 151)
    return (225, 232, 240)


def draw_frame(visible_lines: list[str], font: ImageFont.ImageFont) -> Image.Image:
    image = Image.new("RGB", (GIF_WIDTH, GIF_HEIGHT), (8, 13, 23))
    draw = ImageDraw.Draw(image)

    # Terminal frame.
    draw.rounded_rectangle((28, 24, GIF_WIDTH - 28, GIF_HEIGHT - 24), radius=14, fill=(13, 19, 33))
    draw.rounded_rectangle((28, 24, GIF_WIDTH - 28, 72), radius=14, fill=(28, 38, 55))
    draw.rectangle((28, 52, GIF_WIDTH - 28, 72), fill=(28, 38, 55))
    for index, color in enumerate(((255, 95, 87), (255, 189, 46), (40, 201, 64))):
        x = 54 + index * 26
        draw.ellipse((x, 42, x + 12, 54), fill=color)

    title_font = load_font(18)
    draw.text((144, 40), "Apolysis Codex live demo - host evidence vs declared intent", fill=(213, 221, 235), font=title_font)

    y = 94
    line_height = 29
    for line in visible_lines[-15:]:
        draw.text((56, y), line, fill=line_color(line), font=font)
        y += line_height

    footer_font = load_font(17)
    footer = "validated local live run | fake credential target redacted as path_token:*"
    draw.text((56, GIF_HEIGHT - 58), footer, fill=(148, 163, 184), font=footer_font)
    return image


def render_gif(lines: list[str]) -> None:
    font = load_font(21)
    wrapped = wrap_lines(lines)
    reveal_counts = list(range(1, len(wrapped) + 1))
    if reveal_counts:
        reveal_counts.extend([len(wrapped)] * 6)
    frames = [draw_frame(wrapped[:count], font) for count in reveal_counts]
    durations = [650 if count < len(wrapped) else 900 for count in reveal_counts]
    frames[0].save(
        GIF,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )


def main() -> None:
    lines = load_public_transcript()
    render_cast(lines)
    render_gif(lines)
    print(f"wrote {CAST.relative_to(REPO_ROOT)}")
    print(f"wrote {GIF.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
