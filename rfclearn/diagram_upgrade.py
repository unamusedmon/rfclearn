"""Higher-quality RFC diagram rendering and post-processing.

The RFC source corpus still contains a lot of fixed-width ASCII diagrams.
This module upgrades those blocks into responsive SVG cards while preserving
the original text as accessible fallback metadata.

It is intentionally defensive: RFC diagrams vary wildly, and this renderer
should improve the common cases without breaking odd historical documents.
"""

from __future__ import annotations

import html
import re
import textwrap
from pathlib import Path
from typing import Any, Iterable

from .config import SITE_DIR

ASCII_BLOCK_RE = re.compile(
    r"(?P<open><pre(?P<attrs>[^>]*)>)(?P<body>.*?)(?P<close></pre>)",
    flags=re.IGNORECASE | re.DOTALL,
)

UPGRADED_MARKER = "data-rfclearn-diagram=\"svg-upgrade\""


def _looks_like_diagram(text: str) -> bool:
    """Return True when a fixed-width block is probably an ASCII diagram."""
    clean = html.unescape(re.sub(r"<[^>]+>", "", text)).strip("\n")
    if not clean:
        return False

    lines = [line.rstrip("\n") for line in clean.splitlines() if line.strip()]
    if len(lines) < 2:
        return False

    diagram_chars = sum(ch in "+-|_:/\\<>[]{}=*~^`" for ch in clean)
    letters = sum(ch.isalpha() for ch in clean)
    longest_line = max(len(line) for line in lines)

    has_ruling = any(re.search(r"[-=+_]{3,}|\|.*\||\+[-=]+", line) for line in lines)
    has_arrows = any(("->" in line or "<-" in line or "-->" in line or "<--" in line) for line in lines)
    density = diagram_chars / max(len(clean), 1)

    return longest_line >= 16 and (has_ruling or has_arrows) and density >= 0.10 and letters < len(clean) * 0.75


def _normalize_ascii(text: str) -> list[str]:
    clean = html.unescape(re.sub(r"<[^>]+>", "", text))
    clean = clean.replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    lines = [line.rstrip() for line in clean.splitlines()]
    return textwrap.dedent("\n".join(lines)).splitlines()


def _line_segments(line: str) -> list[tuple[int, int, str]]:
    """Group a fixed-width line into text/rule segments for SVG rendering."""
    segments: list[tuple[int, int, str]] = []
    for match in re.finditer(r"([+\-|_=]{2,}|[A-Za-z0-9][A-Za-z0-9 .,:;()/\[\]#'\"-]{1,})", line):
        text = match.group(0).strip()
        if text:
            segments.append((match.start(), match.end(), text))
    return segments


def _svg_text(text: str, x: float, y: float, *, size: int = 13, weight: int = 500) -> str:
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" font-weight="{weight}" '
        f'font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" '
        f'fill="currentColor">{html.escape(text)}</text>'
    )


def render_ascii_diagram_svg(raw: str, *, title: str = "RFC diagram") -> str:
    """Render an ASCII diagram as a responsive SVG card."""
    lines = _normalize_ascii(raw)
    if not lines:
        return ""

    max_cols = max(len(line) for line in lines)
    char_w = 8.4
    line_h = 22
    pad_x = 20
    pad_y = 24
    width = max(360, int(max_cols * char_w + pad_x * 2))
    height = max(120, int(len(lines) * line_h + pad_y * 2))

    svg_parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}" '
        'xmlns="http://www.w3.org/2000/svg" class="rfc-diagram-svg">',
        '<defs>',
        '<linearGradient id="rfclearnDiagramBg" x1="0" y1="0" x2="1" y2="1">',
        '<stop offset="0%" stop-color="currentColor" stop-opacity="0.055"/>',
        '<stop offset="100%" stop-color="currentColor" stop-opacity="0.015"/>',
        '</linearGradient>',
        '</defs>',
        f'<rect x="1" y="1" width="{width-2}" height="{height-2}" rx="18" fill="url(#rfclearnDiagramBg)" '
        'stroke="currentColor" stroke-opacity="0.20"/>',
    ]

    for row, line in enumerate(lines):
        y = pad_y + row * line_h + 14
        for start, end, segment in _line_segments(line):
            x = pad_x + start * char_w
            seg_w = max(6, (end - start) * char_w)
            stripped = segment.strip()
            if re.fullmatch(r"[+\-|_=]{2,}", stripped):
                svg_parts.append(
                    f'<rect x="{x:.1f}" y="{y-9:.1f}" width="{seg_w:.1f}" height="2.5" rx="1.25" '
                    'fill="currentColor" opacity="0.34"/>'
                )
            else:
                svg_parts.append(_svg_text(stripped, x, y, size=13, weight=600 if row == 0 else 500))

    original = "\n".join(lines)
    svg_parts.append(f"<desc>{html.escape(original)}</desc>")
    svg_parts.append("</svg>")

    return (
        f'<figure class="rfc-diagram-upgrade" {UPGRADED_MARKER}>'
        '<div class="rfc-diagram-frame">'
        + "".join(svg_parts)
        + "</div>"
        f'<details class="rfc-diagram-source"><summary>Original ASCII</summary>'
        f'<pre>{html.escape(original)}</pre></details>'
        "</figure>"
    )


def render_modern_ascii_diagram(*args: Any, **kwargs: Any) -> str:
    """Compatibility wrapper for the builder's existing diagram renderer."""
    raw = ""
    title = kwargs.get("title") or kwargs.get("caption") or "RFC diagram"

    if args:
        first = args[0]
        if isinstance(first, str):
            raw = first
        elif isinstance(first, Iterable):
            raw = "\n".join(str(item) for item in first)
    if not raw:
        raw = str(kwargs.get("diagram") or kwargs.get("text") or "")

    if not _looks_like_diagram(raw):
        return f'<pre class="rfc-source-pre">{html.escape(raw)}</pre>'

    return render_ascii_diagram_svg(raw, title=str(title))


def render_header_layout_svg(*args: Any, **kwargs: Any) -> str:
    """Render known header-reference field lists as clean SVG packet maps."""
    title = str(kwargs.get("title") or "Protocol header")
    fields = kwargs.get("fields")

    for value in args:
        if isinstance(value, str) and title == "Protocol header":
            title = value
        elif isinstance(value, dict):
            title = str(value.get("title", title))
            fields = value.get("fields", fields)
        elif isinstance(value, (list, tuple)) and value and all(isinstance(item, (list, tuple)) for item in value):
            fields = value

    if not fields:
        return ""

    rows: list[tuple[str, int, str]] = []
    for field in fields:
        try:
            name = str(field[0])
            bits = int(field[1])
            note = str(field[2]) if len(field) > 2 else ""
        except Exception:
            continue
        rows.append((name, max(bits, 1), note))

    if not rows:
        return ""

    width = 980
    row_h = 54
    pad = 28
    title_h = 46
    height = title_h + pad + len(rows) * row_h + pad
    total_bits = max(sum(bits for _name, bits, _note in rows), 32)

    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}" '
        'xmlns="http://www.w3.org/2000/svg" class="rfc-header-svg">',
        f'<rect x="1" y="1" width="{width-2}" height="{height-2}" rx="22" fill="currentColor" '
        'fill-opacity="0.035" stroke="currentColor" stroke-opacity="0.18"/>',
        _svg_text(title, pad, 34, size=18, weight=800),
    ]

    y = title_h + 12
    for index, (name, bits, note) in enumerate(rows):
        x = pad
        usable = width - pad * 2
        bar_w = max(90, usable * min(bits, total_bits) / total_bits)
        opacity = 0.10 + (index % 3) * 0.035
        parts.append(
            f'<rect x="{x}" y="{y}" width="{usable}" height="{row_h-10}" rx="12" '
            'fill="currentColor" fill-opacity="0.035"/>'
        )
        parts.append(
            f'<rect x="{x}" y="{y}" width="{bar_w:.1f}" height="{row_h-10}" rx="12" '
            f'fill="currentColor" fill-opacity="{opacity:.3f}"/>'
        )
        parts.append(_svg_text(name, x + 14, y + 22, size=14, weight=800))
        parts.append(_svg_text(f"{bits} bits", x + usable - 80, y + 22, size=12, weight=700))
        if note:
            clipped = note if len(note) <= 118 else note[:115].rstrip() + "..."
            parts.append(_svg_text(clipped, x + 14, y + 41, size=11, weight=450))
        y += row_h

    parts.append("</svg>")
    return '<figure class="rfc-header-upgrade" data-rfclearn-diagram="header-svg">' + "".join(parts) + "</figure>"


def upgrade_html_diagrams(document: str) -> str:
    """Replace remaining raw ASCII <pre> blocks with SVG upgrades."""
    def replace(match: re.Match[str]) -> str:
        attrs = match.group("attrs") or ""
        body = match.group("body")
        whole = match.group(0)
        if "rfc-diagram-source" in attrs or UPGRADED_MARKER in whole:
            return whole
        if not _looks_like_diagram(body):
            return whole
        return render_ascii_diagram_svg(body)

    return ASCII_BLOCK_RE.sub(replace, document)


def write_diagram_css(asset_dir: Path) -> None:
    asset_dir.mkdir(parents=True, exist_ok=True)
    css_path = asset_dir / "diagram-upgrades.css"
    css_path.write_text(
        """
.rfc-diagram-upgrade,
.rfc-header-upgrade {
  margin: 1.5rem 0;
}

.rfc-diagram-frame,
.rfc-header-upgrade {
  overflow-x: auto;
}

.rfc-diagram-svg,
.rfc-header-svg {
  display: block;
  width: 100%;
  min-width: 42rem;
  height: auto;
}

.rfc-diagram-source {
  margin-top: 0.6rem;
  font-size: 0.9rem;
  opacity: 0.82;
}

.rfc-diagram-source summary {
  cursor: pointer;
  user-select: none;
}

.rfc-diagram-source pre {
  overflow-x: auto;
  padding: 0.8rem;
  border-radius: 0.75rem;
  background: color-mix(in srgb, currentColor 7%, transparent);
}
""".strip()
        + "\n",
        encoding="utf-8",
    )


def ensure_css_link(document: str) -> str:
    href = "assets/diagram-upgrades.css"
    if href in document:
        return document
    link = '<link rel="stylesheet" href="../assets/diagram-upgrades.css">'
    if "</head>" in document:
        return document.replace("</head>", f"{link}\n</head>", 1)
    return link + "\n" + document


def postprocess_site(site_dir: Path = SITE_DIR) -> int:
    """Upgrade generated RFC pages in-place.

    Returns the number of pages changed.
    """
    rfc_dir = site_dir / "rfc"
    if not rfc_dir.exists():
        return 0

    write_diagram_css(site_dir / "assets")

    changed = 0
    for path in sorted(rfc_dir.glob("*.html")):
        original = path.read_text(encoding="utf-8", errors="replace")
        upgraded = ensure_css_link(upgrade_html_diagrams(original))
        if upgraded != original:
            path.write_text(upgraded, encoding="utf-8")
            changed += 1
    return changed


def install_diagram_upgrade(builder_module: Any) -> None:
    """Patch the existing builder module without requiring a large rewrite."""
    builder_module.render_modern_ascii_diagram = render_modern_ascii_diagram
    builder_module.render_header_layout_svg = render_header_layout_svg
    original_main = builder_module.main

    def main_with_diagram_upgrade(*args: Any, **kwargs: Any) -> Any:
        result = original_main(*args, **kwargs)
        postprocess_site()
        return result

    builder_module.main = main_with_diagram_upgrade
