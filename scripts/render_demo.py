#!/usr/bin/env python3
"""Turn a screen recording of SentryTower into an animated SVG (the README demo) or into still frames.

Usage:
    python3 scripts/render_demo.py RECORDING.jsonl --svg OUT.svg [--speed 1.0] [--max-gap 2.5] [--columns 100] [--rows 32]
        [--cut START:END:FACTOR ...] [--squeeze "FROM|TEXT:TO|TEXT:SECONDS"] [--fps 12] [--hold 4] [--title TEXT]
        [--prompt "FOLDER $ COMMAND"]
    python3 scripts/render_demo.py RECORDING.jsonl --still OUT.svg [--at SECONDS]   (the last frame without --at)
    python3 scripts/render_demo.py RECORDING.jsonl --html OUT.html [--at SECONDS ...]

A recording is what ``SENTRYTOWER_RECORD=FILE`` writes: one JSON line for
each change of the screen (``print``: lines that stay; ``draw``: the live
region). The renderer rebuilds the terminal (the last ``--rows`` lines of
the scrollback and the live region) at each change and draws each frame
with SVG rectangles and text. A half block (``▀``, ``▄``) becomes two
rectangles, so the pixel art of the agent is exact in any font.

Time: each pause is at most ``--max-gap`` seconds; ``--cut A:B:F`` plays the
part from A to B seconds of the recording F times faster; ``--squeeze``
plays the part from the first change that shows one text to the first
later change that shows another text in the given seconds (the long middle
of an audit; ``|`` separates alternative texts). ``--fps`` keeps at most
that many frames a second. The last frame stays ``--hold`` seconds. The
view scrolls like a terminal: down when the lines pass the last row, never
back up. The SVG defines each distinct line once and each frame uses the
lines it shows, so a long recording stays small. ``--prompt`` starts the
animation with a shell prompt that types the command of the recording.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
from dataclasses import dataclass
from pathlib import Path

CELL_W, CELL_H = 8.4, 18.0
PAD_X, PAD_TOP, PAD_BOTTOM = 18.0, 44.0, 16.0
FG, BG, DIM = "#e8e6e1", "#131317", "#8e8a83"
FONT = "ui-monospace, 'SF Mono', SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"


@dataclass
class Frame:
    t: float
    lines: list[list[tuple[str, dict]]]
    # The text of the lines of the change itself (for --squeeze).
    text: str = ""


def load(path: Path) -> tuple[list[Frame], int, int]:
    scrollback: list[list[tuple[str, dict]]] = []
    live: list[list[tuple[str, dict]]] = []
    frames: list[Frame] = []
    width, height = 100, 32
    for raw in path.read_text().splitlines():
        event = json.loads(raw)
        lines = [[(text, style) for text, style in line] for line in event.get("lines") or []]
        if event["kind"] == "size":
            width, height = int(event.get("width") or width), int(event.get("height") or height)
            continue
        if event["kind"] == "print":
            scrollback.extend(lines)
        elif event["kind"] == "draw":
            live = lines
        text = "\n".join("".join(part for part, _ in line) for line in lines)
        frames.append(Frame(float(event["t"]), [*scrollback, *live], text))
    return frames, width, height


def find(frames: list[Frame], texts: str, after: float = 0.0) -> float | None:
    """The time of the first change at or after ``after`` that shows one of the texts (``|`` separates them)."""
    options = [item for item in texts.split("|") if item]
    for frame in frames:
        if frame.t >= after and any(item in frame.text for item in options):
            return frame.t
    return None


def squeeze_cut(frames: list[Frame], spec: str) -> tuple[float, float, float]:
    """A --cut of the part between two texts that lasts the given seconds."""
    start_text, end_text, seconds = spec.rsplit(":", 2)
    start = find(frames, start_text)
    end = find(frames, end_text, start or 0.0) if start is not None else None
    if start is None or end is None or end <= start:
        raise SystemExit(f"render_demo: the recording has no part from {start_text!r} to {end_text!r}")
    return start, end, max(1.0, (end - start) / float(seconds))


def with_prompt(frames: list[Frame], prompt: str, *, typing: float = 0.055) -> tuple[list[Frame], float]:
    """The frames after a shell prompt that types the command ("~/code/app $ sentrytower setup"), and the added seconds."""
    folder, _, command = prompt.partition(" $ ")
    head = [(folder + " ", {"fg": [122, 162, 247], "bold": True}), ("$ ", {"dim": True})]
    cursor = ("▌", {"fg": [224, 181, 120]})
    start = 0.5
    out = [Frame(0.0, [[*head, cursor]])]
    out += [Frame(start + count * typing, [[*head, (command[:count], {"bold": True}), cursor]]) for count in range(1, len(command) + 1)]
    shift = start + len(command) * typing + 0.6
    line = [*head, (command, {"bold": True})]
    out += [Frame(frame.t + shift, [line, *frame.lines], frame.text) for frame in frames]
    return out, shift


def retime(
    frames: list[Frame],
    *,
    speed: float,
    max_gap: float,
    cuts: list[tuple[float, float, float]],
    fps: float = 50.0,
    cut_fps: float | None = None,
) -> list[Frame]:
    """The frames on the time line of the animation, at most ``fps`` frames a second (``cut_fps`` in a faster part)."""
    out: list[Frame] = []
    clock = 0.0
    previous = None
    for frame in frames:
        in_cut = False
        if previous is not None:
            gap = frame.t - previous
            for start, end, factor in cuts:
                if start < frame.t <= end:
                    gap /= factor
                    in_cut = True
            clock += min(gap / speed, max_gap)
        previous = frame.t
        step = 1.0 / (cut_fps if in_cut and cut_fps else fps)
        if out and clock - out[-1].t < step:
            out[-1] = Frame(out[-1].t, frame.lines, frame.text)
        else:
            out.append(Frame(clock, frame.lines, frame.text))
    return out


def color(value: object, default: str) -> str:
    if isinstance(value, list) and len(value) == 3:
        red, green, blue = (int(part) for part in value)
        return f"#{red:02x}{green:02x}{blue:02x}"
    return default


# Characters above U+2E80 that take one cell (box drawing, symbols, the spinner); other ones take two.
NARROW = "─━│◆◇●○❯✓✗★▲·…▔⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏└┌■•▌"
BLOCKS = "▀▄█"


def char_cells(char: str) -> int:
    return 2 if ord(char) > 0x2E80 and char not in NARROW else 1


def split_art(line: list[tuple[str, dict]]) -> tuple[list[tuple[str, dict]], list[tuple[str, dict]], int]:
    """The pixel art at the start of a line (half blocks and spaces), the rest of the line, and the cells of the art.

    The art of the agent stays the same while the text beside it changes, so the SVG defines it once.
    """
    art: list[tuple[str, dict]] = []
    width = 0
    for index, (text, style) in enumerate(line):
        if text and all(char in BLOCKS + " " for char in text):
            art.append((text, style))
            width += sum(char_cells(char) for char in text)
            continue
        return art, line[index:], width
    return art, [], width


def line_svg(line: list[tuple[str, dict]], y: float, x0: int = 0) -> str:
    """One terminal line at height ``y``, from cell ``x0``: background and half-block rectangles, then text runs."""
    rects, texts = [], []
    x = PAD_X + x0 * CELL_W
    for text, style in line:
        fg = color(style.get("fg"), FG)
        bg = style.get("bg")
        run_start = x
        run = ""
        for char in text:
            if char in "▀▄█":
                if run:
                    texts.append((run_start, run, style))
                    run = ""
                top = fg if char in "▀█" else (color(bg, "") if bg else "")
                bottom = fg if char in "▄█" else (color(bg, "") if bg else "")
                if top:
                    rects.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{CELL_W + 0.3:.1f}" height="{CELL_H / 2 + 0.3:.1f}" fill="{top}"/>')
                if bottom:
                    rects.append(
                        f'<rect x="{x:.1f}" y="{y + CELL_H / 2:.1f}" width="{CELL_W + 0.3:.1f}" height="{CELL_H / 2 + 0.3:.1f}" fill="{bottom}"/>'
                    )
                x += CELL_W
                run_start = x
                continue
            if bg:
                rects.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{CELL_W + 0.3:.1f}" height="{CELL_H:.1f}" fill="{color(bg, BG)}"/>')
            run += char
            x += CELL_W * char_cells(char)
        if run:
            texts.append((run_start, run, style))
    parts = rects
    for start, run, style in texts:
        if not run.strip():
            continue
        attributes = [f'x="{start:.1f}"', f'y="{y + CELL_H * 0.74:.1f}"']
        fill = color(style.get("fg"), DIM if style.get("dim") else FG)
        attributes.append(f'fill="{fill}"')
        if style.get("dim") and not style.get("fg"):
            attributes.append('opacity="0.9"')
        if style.get("bold"):
            attributes.append('font-weight="700"')
        if style.get("italic"):
            attributes.append('font-style="italic"')
        attributes.append(f'textLength="{CELL_W * len(run):.1f}"')
        parts.append(f'<text {" ".join(attributes)} xml:space="preserve">{html.escape(run)}</text>')
    return "".join(parts)


def windows(frames: list[Frame], rows: int) -> list[list[list[tuple[str, dict]]]]:
    """The rows that a terminal shows at each frame: it scrolls down when the lines pass the last row, never back up."""
    top = 0
    out = []
    for frame in frames:
        top = max(top, len(frame.lines) - rows)
        out.append(frame.lines[top : top + rows])
    return out


def to_svg(frames: list[Frame], columns: int, rows: int, *, hold: float, title: str, animate: bool = True) -> str:
    width = PAD_X * 2 + CELL_W * columns
    height = PAD_TOP + PAD_BOTTOM + CELL_H * rows
    total = frames[-1].t + hold
    line_ids: dict[str, str] = {}
    defs: list[str] = []
    bodies: list[str] = []
    for index, shown in enumerate(windows(frames, rows)):
        uses = []
        for row, line in enumerate(shown):
            if not any(text.strip() for text, _ in line):
                continue
            art, rest, offset = split_art(line)
            has_art = any(char in BLOCKS for text, _ in art for char in text)
            parts = [(art, 0), (rest, offset)] if has_art else [(line, 0)]
            for part, x0 in parts:
                if not any(text.strip() for text, _ in part):
                    continue
                key = json.dumps([x0, part], sort_keys=True)
                if key not in line_ids:
                    identifier = "l" + hashlib.sha256(key.encode()).hexdigest()[:10]
                    line_ids[key] = identifier
                    defs.append(f'<g id="{identifier}">{line_svg(part, 0.0, x0)}</g>')
                uses.append(f'<use href="#{line_ids[key]}" y="{PAD_TOP + row * CELL_H:.1f}"/>')
        bodies.append(f'<g class="f f{index}">{"".join(uses)}</g>' if animate else f"<g>{''.join(uses)}</g>")
    keyframes = []
    for index, frame in enumerate(frames if animate else []):
        start = frame.t / total * 100
        end = (frames[index + 1].t if index + 1 < len(frames) else total) / total * 100
        keyframes.append(
            f"@keyframes k{index}{{0%,{max(0, start - 0.0001):.4f}%{{visibility:hidden}}{start:.4f}%,{max(start, end - 0.0001):.4f}%"
            f"{{visibility:visible}}{end:.4f}%,100%{{visibility:hidden}}}}.f{index}{{animation:k{index} {total:.2f}s step-end infinite}}"
        )
    chrome = (
        f'<rect width="{width:.1f}" height="{height:.1f}" rx="10" fill="{BG}"/>'
        f'<circle cx="22" cy="20" r="6" fill="#ff5f57"/><circle cx="42" cy="20" r="6" fill="#febc2e"/><circle cx="62" cy="20" r="6" fill="#28c840"/>'
        f'<text x="{width / 2:.1f}" y="25" fill="{DIM}" font-size="12" text-anchor="middle" font-family="-apple-system, Segoe UI, Helvetica, Arial, sans-serif">{html.escape(title)}</text>'
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{width:.0f}" height="{height:.0f}" '
        f'viewBox="0 0 {width:.1f} {height:.1f}" font-family="{FONT}" font-size="14">'
        f"<title>{html.escape(title)}</title>"
        + (
            f"<style>.f{{visibility:hidden}}{''.join(keyframes)}@media (prefers-reduced-motion: reduce){{.f{{animation:none}}.f{len(frames) - 1}{{visibility:visible}}}}</style>"
            if animate
            else ""
        )
        + f"<defs>{''.join(defs)}</defs>{chrome}{''.join(bodies)}</svg>\n"
    )


def still(frames: list[Frame], moment: float | None, columns: int, rows: int, *, title: str, after: str | None = None) -> str:
    """One frame as a static SVG: the frame at ``moment`` seconds of the recording, or the last frame.

    With ``after``, the image starts below the last line that holds that text (an empty text: at the first
    line) and is as tall as its lines.
    """
    index = len(frames) - 1 if moment is None else max(0, max((i for i, item in enumerate(frames) if item.t <= moment), default=0))
    lines = frames[index].lines
    if after is not None:
        marks = [row for row, line in enumerate(lines) if after in "".join(part for part, _ in line)] if after else [-1]
        if not marks:
            raise SystemExit(f"render_demo: no line of the frame holds {after!r}")
        lines = lines[marks[-1] + 1 :]
        while lines and not "".join(part for part, _ in lines[0]).strip():
            lines = lines[1:]
        while lines and not "".join(part for part, _ in lines[-1]).strip():
            lines = lines[:-1]
        return to_svg([Frame(0.0, lines)], columns, len(lines), hold=1.0, title=title, animate=False)
    top = max(0, max(len(frame.lines) for frame in frames[: index + 1]) - rows)
    top = min(top, max(0, len(lines) - 1))
    return to_svg([Frame(0.0, lines[top:])], columns, rows, hold=1.0, title=title, animate=False)


def to_html(frames: list[Frame], columns: int, rows: int, at: list[float]) -> str:
    picks = []
    for moment in at or [frames[-1].t]:
        frame = next((item for item in reversed(frames) if item.t <= moment), frames[0])
        picks.append(to_svg([Frame(0.0, frame.lines)], columns, rows, hold=1.0, title=f"t = {moment:.1f} s"))
    return "<!doctype html><meta charset=utf-8><body style='background:#222;margin:0;padding:12px;display:grid;gap:12px'>" + "".join(picks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("recording", type=Path)
    parser.add_argument("--svg", type=Path)
    parser.add_argument("--still", type=Path, help="one frame as a static SVG (the last frame, or the frame of --at)")
    parser.add_argument("--still-after", help='the still starts below the last line with this text ("": at the top) and fits its lines')
    parser.add_argument("--html", type=Path)
    parser.add_argument("--at", type=float, action="append", default=[])
    parser.add_argument("--squeeze", action="append", default=[], help="FROM_TEXT:TO_TEXT:SECONDS")
    parser.add_argument("--fps", type=float, default=12.0)
    parser.add_argument("--cut-fps", type=float, default=6.0, help="the frames a second of the parts that play faster")
    parser.add_argument("--speed", type=float, default=1.0)
    parser.add_argument("--max-gap", type=float, default=2.5)
    parser.add_argument("--cut", action="append", default=[], help="START:END:FACTOR in seconds of the recording")
    parser.add_argument("--hold", type=float, default=4.0)
    parser.add_argument("--columns", type=int)
    parser.add_argument("--rows", type=int)
    parser.add_argument("--title", default="sentrytower")
    parser.add_argument("--prompt", help='a shell prompt that types the command first: "FOLDER $ COMMAND"')
    args = parser.parse_args()
    frames, width, height = load(args.recording)
    columns, rows = args.columns or width, args.rows or height
    if args.html:
        args.html.write_text(to_html(frames, columns, rows, args.at))
        print(f"wrote {args.html}")
    if args.still:
        args.still.write_text(still(frames, args.at[0] if args.at else None, columns, rows, title=args.title, after=args.still_after))
        print(f"wrote {args.still}")
    if args.svg:
        cuts = [tuple(float(part) for part in item.split(":")) for item in args.cut]
        cuts += [squeeze_cut(frames, spec) for spec in args.squeeze]
        for start, end, factor in cuts:
            print(f"render_demo: {start:.1f} s to {end:.1f} s plays {factor:.0f} times faster")
        if args.prompt:
            frames, shift = with_prompt(frames, args.prompt)
            cuts = [(start + shift, end + shift, factor) for start, end, factor in cuts]
        timed = retime(frames, speed=args.speed, max_gap=args.max_gap, cuts=cuts, fps=args.fps, cut_fps=args.cut_fps)  # type: ignore[arg-type]
        text = to_svg(timed, columns, rows, hold=args.hold, title=args.title)
        args.svg.write_text(text)
        print(f"wrote {args.svg}: {len(timed)} frames, {timed[-1].t + args.hold:.1f} s, {len(text) // 1024} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
