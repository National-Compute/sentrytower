#!/usr/bin/env python3
"""Make the agent art: the vector images of the five colours and the pixel art of the terminal.

Usage: python3 scripts/make_mascot.py [--chrome PATH]

The agent is the tower of ``AgentAvatar`` of the web app (viewBox 0 0 120
120). The script writes:

- ``docs/assets/agent-<colour>.svg``: the vector agent of each colour;
- ``src/sentrytower/ui/mascot_data.py``: the pixel art of each colour at the
  widths of ``WIDTHS``, as RGBA bytes (zlib, base64).

Pixel art: headless Chrome draws the body (its gradients and highlight)
and each feature of the face as separate layers at 420 x 460 pixels. A
pixel of the art is in the body when the mean coverage of it and of its
mirror pixel is at least one half (the shape stays symmetric). The face is
placed by rule, mirror-symmetric: the eyes (with a highlight at 20 pixels
and wider), the cheeks and the smile. The data needs no Chrome at run time.
"""

from __future__ import annotations

import argparse
import base64
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WIDTHS = (26, 14)
COLORS = {
    "cobalt": ("#a9b5ff", "#5068f4", "#2c3fc0"),
    "moss": ("#b4e0bd", "#5e9f6f", "#376f47"),
    "coral": ("#ffc6b4", "#ec7a5d", "#bf4f35"),
    "plum": ("#dcc6ff", "#9b6ee2", "#6c44b3"),
    "sand": ("#fbe6c2", "#e0b578", "#ad8146"),
}
TOWER = (
    "M22 88C22 97.5 29 104 38.5 104L81.5 104C91 104 98 97.5 98 88L93.5 26.5"
    "C93.5 22.6 90.5 20 86.8 20L83.7 20C80 20 77 22.6 77 26.5L77 28.5"
    "C77 31.6 75 33.4 72.5 33.4C70 33.4 68 31.6 68 28.5L68 26.5"
    "C68 22.6 65 20 61.5 20L58.5 20C55 20 52 22.6 52 26.5L52 28.5"
    "C52 31.6 50 33.4 47.5 33.4C45 33.4 43 31.6 43 28.5L43 26.5"
    "C43 22.6 40 20 36.3 20L33.2 20C29.5 20 26.5 22.6 26.5 26.5Z"
)
# The crop of the pixel art: the character without the ground shadow.
CROP = (18, 14, 84, 92)
RASTER = (420, 460)
EYE, GLINT, MOUTH, CHEEK = (23, 23, 28), (255, 255, 255), (38, 36, 42), (255, 123, 123)


def defs(light: str, base: str, dark: str) -> str:
    return (
        f'<defs><radialGradient id="b" cx="32%" cy="24%" r="92%"><stop offset="0" stop-color="{light}"/>'
        f'<stop offset="0.52" stop-color="{base}"/><stop offset="1" stop-color="{dark}"/></radialGradient>'
        '<linearGradient id="s" x1="0" y1="0" x2="0" y2="1"><stop offset="0.5" stop-color="#000" stop-opacity="0"/>'
        '<stop offset="1" stop-color="#000" stop-opacity="0.18"/></linearGradient>'
        '<filter id="f" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="2.6"/></filter></defs>'
    )


def vector_svg(name: str) -> str:
    """The agent of one colour, as the web app draws it (with the ground shadow)."""
    light, base, dark = COLORS[name]
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" width="120" height="120" role="img" '
        f'aria-label="The SentryTower agent in {name}">'
        + defs(light, base, dark)
        + '<ellipse cx="60" cy="107" rx="31" ry="4.6" fill="#16161a" opacity="0.14" filter="url(#f)"/>'
        f'<path d="{TOWER}" fill="url(#b)"/><path d="{TOWER}" fill="url(#s)"/>'
        '<ellipse cx="43" cy="41" rx="11.5" ry="5" fill="#fff" opacity="0.34" filter="url(#f)"/>'
        '<circle cx="41" cy="73" r="4.8" fill="#ff7b7b" opacity="0.24"/><circle cx="79" cy="73" r="4.8" fill="#ff7b7b" opacity="0.24"/>'
        '<ellipse cx="49" cy="63" rx="4.3" ry="5.5" fill="#17171c"/><ellipse cx="71" cy="63" rx="4.3" ry="5.5" fill="#17171c"/>'
        '<circle cx="50.5" cy="61" r="1.4" fill="#fff"/><circle cx="72.5" cy="61" r="1.4" fill="#fff"/>'
        '<path d="M55.2 73.6Q60 77.6 64.8 73.6" fill="none" stroke="#17171c" stroke-width="2.3" stroke-linecap="round" opacity="0.86"/>'
        "</svg>\n"
    )


def layer_svg(body: str) -> str:
    x, y, w, h = CROP
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{x} {y} {w} {h}" width="{RASTER[0]}" height="{RASTER[1]}">{body}</svg>'


def layers() -> dict[str, str]:
    out = {}
    for name, (light, base, dark) in COLORS.items():
        out[f"body-{name}"] = layer_svg(
            defs(light, base, dark) + f'<path d="{TOWER}" fill="url(#b)"/><path d="{TOWER}" fill="url(#s)"/>'
            '<ellipse cx="43" cy="41" rx="11.5" ry="5" fill="#fff" opacity="0.34" filter="url(#f)"/>'
        )
    return out


def read_png(path: Path) -> tuple[int, int, list[bytes]]:
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"{path} is not a PNG file")
    pos, idat, width, height = 8, b"", 0, 0
    while pos < len(data):
        length, kind = struct.unpack(">I4s", data[pos : pos + 8])
        body = data[pos + 8 : pos + 8 + length]
        if kind == b"IHDR":
            width, height, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", body)
            if (depth, ctype, interlace) != (8, 6, 0):
                raise ValueError("the rasterizer must write 8-bit RGBA without interlace")
        elif kind == b"IDAT":
            idat += body
        pos += 12 + length
    raw = zlib.decompress(idat)
    stride, rows, prev, index = width * 4, [], bytearray(width * 4), 0
    for _ in range(height):
        kind = raw[index]
        line = bytearray(raw[index + 1 : index + 1 + stride])
        index += 1 + stride
        for x in range(stride):
            a = line[x - 4] if x >= 4 else 0
            b = prev[x]
            c = prev[x - 4] if x >= 4 else 0
            if kind == 1:
                line[x] = (line[x] + a) & 255
            elif kind == 2:
                line[x] = (line[x] + b) & 255
            elif kind == 3:
                line[x] = (line[x] + (a + b) // 2) & 255
            elif kind == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[x] = (line[x] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        rows.append(bytes(line))
        prev = line
    return width, height, rows


def blocks(png: tuple[int, int, list[bytes]], w: int, h: int) -> list[list[tuple[float, tuple[int, int, int] | None]]]:
    """For each pixel of a w x h grid: the mean alpha and the alpha-weighted colour of its block."""
    width, height, rows = png
    grid = []
    for gy in range(h):
        y0, y1 = gy * height // h, (gy + 1) * height // h
        row = []
        for gx in range(w):
            x0, x1 = gx * width // w, (gx + 1) * width // w
            sr = sg = sb = sa = n = 0
            for y in range(y0, y1):
                line = rows[y]
                for x in range(x0, x1):
                    r, g, b, a = line[4 * x : 4 * x + 4]
                    sr += r * a
                    sg += g * a
                    sb += b * a
                    sa += a
                    n += 1
            color = (round(sr / sa), round(sg / sa), round(sb / sa)) if sa else None
            row.append((sa / (255 * n), color))
        grid.append(row)
    return grid


def mix(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return (round(a[0] + (b[0] - a[0]) * t), round(a[1] + (b[1] - a[1]) * t), round(a[2] + (b[2] - a[2]) * t))


def pixel_art(body_png: tuple[int, int, list[bytes]], w: int) -> tuple[int, list[list[tuple[int, int, int] | None]]]:
    x0, y0, vw, vh = CROP
    h = round(w * vh / vw)
    h += h % 2
    body = blocks(body_png, w, h)
    grid: list[list[tuple[int, int, int] | None]] = [[None] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            alpha = (body[y][x][0] + body[y][w - 1 - x][0]) / 2
            if alpha >= 0.5 and body[y][x][1] is not None:
                grid[y][x] = body[y][x][1]

    def px(units: float) -> float:
        return (units - x0) / vw * w

    def py(units: float) -> float:
        return (units - y0) / vh * h

    eye_w = 2 if w >= 20 else 1
    eye_h = 3 if w >= 24 else 2
    left = round(px(49) - eye_w / 2)
    right = w - left - eye_w
    top = round(py(63) - eye_h / 2)
    for start in (left, right):
        for dx in range(eye_w):
            for dy in range(eye_h):
                grid[top + dy][start + dx] = EYE
        if w >= 20:
            grid[top][start + eye_w - 1] = GLINT
    cheek_y = round(py(73))
    cheek_w = 2 if w >= 20 else 1
    cheek_left = round(px(41) - cheek_w / 2)
    for start in (cheek_left, w - cheek_left - cheek_w):
        for dx in range(cheek_w):
            color = grid[cheek_y][start + dx]
            if color is not None:
                grid[cheek_y][start + dx] = mix(color, CHEEK, 0.45)
    mouth_y = round(py(75.2))
    mid = w // 2
    if w >= 20:
        for x, y in ((mid - 2, mouth_y - 1), (mid + 1, mouth_y - 1), (mid - 1, mouth_y), (mid, mouth_y)):
            grid[y][x] = MOUTH
    else:
        grid[mouth_y][mid - 1] = MOUTH
        grid[mouth_y][mid] = MOUTH
    return h, grid


def encode(grid: list[list[tuple[int, int, int] | None]]) -> str:
    raw = bytearray()
    for row in grid:
        for color in row:
            raw += bytes((*color, 255)) if color else bytes(4)
    return base64.b64encode(zlib.compress(bytes(raw), 9)).decode()


def rasterize(chrome: str, svg: str, folder: Path, name: str) -> Path:
    source = folder / f"{name}.svg"
    target = folder / f"{name}.png"
    source.write_text(svg)
    subprocess.run(
        [chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--default-background-color=00000000",
         f"--window-size={RASTER[0]},{RASTER[1]}", f"--screenshot={target}", source.as_uri()],
        check=True, capture_output=True, timeout=120,
    )  # fmt: skip
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--chrome", default="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    args = parser.parse_args()
    assets = ROOT / "docs" / "assets"
    for name in COLORS:
        (assets / f"agent-{name}.svg").write_text(vector_svg(name))
    images: dict[tuple[str, int], tuple[int, int, str]] = {}
    with tempfile.TemporaryDirectory() as folder:
        for key, svg in layers().items():
            png = read_png(rasterize(args.chrome, svg, Path(folder), key))
            name = key.removeprefix("body-")
            for width in WIDTHS:
                height, grid = pixel_art(png, width)
                images[(name, width)] = (width, height, encode(grid))
    lines = [
        '"""The pixel art of the agent (generated by scripts/make_mascot.py; do not edit).',
        "",
        "IMAGES maps (colour, width) to (width, height, RGBA bytes compressed with zlib and encoded with base64).",
        '"""',
        "",
        "IMAGES: dict[tuple[str, int], tuple[int, int, str]] = {",
    ]
    for (name, width), (w, h, data) in sorted(images.items()):
        lines.append(f'    ("{name}", {width}): ({w}, {h}, "{data}"),')
    lines.append("}")
    (ROOT / "src" / "sentrytower" / "ui" / "mascot_data.py").write_text("\n".join(lines) + "\n")
    print(f"wrote {len(images)} images and {len(COLORS)} vector files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
