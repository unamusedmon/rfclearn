"""Readable diagram rendering and post-processing for RFC Learn.

The first diagram pass tried to reinterpret ASCII art into SVG primitives. That
looked bad for real RFCs because historical diagrams are irregular and often use
spacing as meaning. This version is intentionally more conservative:

* known protocol headers become clean responsive HTML packet-field cards
* unknown ASCII diagrams remain faithful, but are displayed in large readable
  monospace panels with better spacing and horizontal scrolling
* generated EPUB/helper SVG charts are left alone
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

UPGRADED_MARKER = "data-rfclearn-diagram"


def _strip_html(text: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", text))


def _looks_like_diagram(text: str) -> bool:
    clean = _strip_html(text).strip("\n")
    if not clean:
        return False
    lines = [line.rstrip("\n") for line in clean.splitlines() if line.strip()]
    if len(lines) < 2:
        return False
    diagram_chars = sum(ch in "+-|_:/\\<>[]{}=*~^`" for ch in clean)
    longest_line = max(len(line) for line in lines)
    has_ruling = any(re.search(r"[-=+_]{3,}|\|.*\||\+[-=]+", line) for line in lines)
    has_arrows = any(token in line for line in lines for token in ("->", "<-", "-->", "<--"))
    density = diagram_chars / max(len(clean), 1)
    return longest_line >= 16 and (has_ruling or has_arrows) and density >= 0.08


def _normalize_ascii(text: str) -> str:
    clean = _strip_html(text)
    clean = clean.replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    lines = [line.rstrip() for line in clean.splitlines()]
    return textwrap.dedent("\n".join(lines)).strip("\n")


def render_ascii_diagram_panel(raw: str, *, title: str = "RFC diagram") -> str:
    """Render unknown ASCII diagrams faithfully, but with sane presentation."""
    original = _normalize_ascii(raw)
    if not original:
        return ""
    return (
        f'<figure class="rfc-diagram-panel" data-rfclearn-diagram="ascii-panel">'
        f'<figcaption>{html.escape(title)}</figcaption>'
        '<div class="rfc-diagram-scroll">'
        f'<pre>{html.escape(original)}</pre>'
        '</div>'
        '</figure>'
    )


def render_modern_ascii_diagram(*args: Any, **kwargs: Any) -> str:
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
        return f'<pre class="rfc-readable-pre">{html.escape(_strip_html(raw))}</pre>'
    return render_ascii_diagram_panel(raw, title=str(title))


def _field_class(bits: int) -> str:
    if bits <= 4:
        return "tiny"
    if bits <= 8:
        return "small"
    if bits <= 16:
        return "medium"
    if bits <= 32:
        return "large"
    return "huge"


def render_header_layout_svg(*args: Any, **kwargs: Any) -> str:
    """Render known header-reference field lists as responsive HTML cards.

    The function name stays for compatibility with the builder, but HTML cards
    are more legible and responsive than the old generated SVG rows.
    """
    title = str(kwargs.get("title") or "Protocol header")
    fields = kwargs.get("fields")
    note = ""

    for value in args:
        if isinstance(value, str) and title == "Protocol header":
            title = value
        elif isinstance(value, dict):
            title = str(value.get("title", title))
            fields = value.get("fields", fields)
            note = str(value.get("note", note) or note)
        elif isinstance(value, (list, tuple)) and value and all(isinstance(item, (list, tuple)) for item in value):
            fields = value

    rows: list[tuple[str, int, str]] = []
    for field in fields or []:
        try:
            name = str(field[0])
            bits = max(int(field[1]), 1)
            field_note = str(field[2]) if len(field) > 2 else ""
        except Exception:
            continue
        rows.append((name, bits, field_note))

    if not rows:
        return ""

    total_bits = max(sum(bits for _name, bits, _note in rows), 32)
    field_cards = []
    for name, bits, field_note in rows:
        pct = max(9, min(100, (bits / total_bits) * 100))
        field_cards.append(
            '<article class="packet-field '
            + _field_class(bits)
            + f'" style="--field-width:{pct:.3f}%">'
            + '<div class="packet-field-top">'
            + f'<strong>{html.escape(name)}</strong>'
            + f'<span>{bits} bit{"s" if bits != 1 else ""}</span>'
            + '</div>'
            + (f'<p>{html.escape(field_note)}</p>' if field_note else '')
            + '</article>'
        )

    return (
        '<figure class="rfc-header-panel" data-rfclearn-diagram="header-panel">'
        '<div class="header-panel-title">'
        f'<h3>{html.escape(title)}</h3>'
        + (f'<p>{html.escape(note)}</p>' if note else '')
        + '</div>'
        '<div class="packet-field-grid">'
        + "".join(field_cards)
        + '</div>'
        '</figure>'
    )


def upgrade_html_diagrams(document: str) -> str:
    """Replace remaining raw ASCII diagram <pre> blocks with readable panels."""
    def replace(match: re.Match[str]) -> str:
        attrs = match.group("attrs") or ""
        body = match.group("body")
        whole = match.group(0)
        if "rfc-diagram-source" in attrs or UPGRADED_MARKER in whole:
            return whole
        if not _looks_like_diagram(body):
            return whole
        return render_ascii_diagram_panel(body)

    return ASCII_BLOCK_RE.sub(replace, document)


def write_diagram_css(asset_dir: Path) -> None:
    asset_dir.mkdir(parents=True, exist_ok=True)
    css_path = asset_dir / "diagram-upgrades.css"
    css_path.write_text(DIAGRAM_CSS.strip() + "\n", encoding="utf-8")


def ensure_css_link(document: str) -> str:
    href = "diagram-upgrades.css"
    if href in document:
        return document
    link = '<link rel="stylesheet" href="../assets/diagram-upgrades.css">'
    if "</head>" in document:
        return document.replace("</head>", f"{link}\n</head>", 1)
    return link + "\n" + document


def postprocess_site(site_dir: Path = SITE_DIR) -> int:
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
    builder_module.render_modern_ascii_diagram = render_modern_ascii_diagram
    builder_module.render_header_layout_svg = render_header_layout_svg
    original_main = builder_module.main

    def main_with_diagram_upgrade(*args: Any, **kwargs: Any) -> Any:
        result = original_main(*args, **kwargs)
        postprocess_site()
        return result

    builder_module.main = main_with_diagram_upgrade


DIAGRAM_CSS = r"""
.rfc-header-panel,
.rfc-diagram-panel {
  max-width: min(1120px, 100%);
  margin: 1.65rem auto;
  border: 1px solid rgba(101,228,255,.18);
  border-radius: 1.35rem;
  background:
    radial-gradient(circle at top left, rgba(101,228,255,.10), transparent 22rem),
    linear-gradient(145deg, rgba(18,27,47,.92), rgba(8,12,23,.88));
  box-shadow: 0 18px 56px rgba(0,0,0,.28), inset 0 1px 0 rgba(255,255,255,.04);
  overflow: hidden;
}

.header-panel-title,
.rfc-diagram-panel figcaption {
  padding: 1rem 1.15rem .85rem;
  border-bottom: 1px solid rgba(255,255,255,.09);
}

.header-panel-title h3,
.rfc-diagram-panel figcaption {
  margin: 0;
  color: var(--cyan, #65e4ff);
  font-size: 1rem;
  font-weight: 900;
  letter-spacing: .045em;
}

.header-panel-title p {
  max-width: 80ch;
  margin: .35rem 0 0;
  color: var(--muted, #9fb0c9);
  font-size: .92rem;
  line-height: 1.5;
}

.packet-field-grid {
  display: flex;
  flex-wrap: wrap;
  gap: .7rem;
  padding: 1rem;
}

.packet-field {
  flex: 1 1 max(13rem, var(--field-width));
  min-width: 11.5rem;
  border: 1px solid rgba(255,255,255,.10);
  border-radius: 1rem;
  padding: .85rem .9rem;
  background:
    linear-gradient(135deg, rgba(101,228,255,.075), rgba(184,156,255,.045)),
    rgba(255,255,255,.035);
}

.packet-field.tiny,
.packet-field.small {
  min-width: 8.5rem;
}

.packet-field.huge {
  flex-basis: min(100%, 24rem);
}

.packet-field-top {
  display: flex;
  gap: .65rem;
  justify-content: space-between;
  align-items: start;
}

.packet-field strong {
  color: #eef7ff;
  font-size: .95rem;
  line-height: 1.25;
}

.packet-field span {
  flex: none;
  border-radius: 999px;
  padding: .14rem .46rem;
  color: #09111e;
  background: var(--cyan, #65e4ff);
  font-size: .72rem;
  font-weight: 950;
}

.packet-field p {
  margin: .5rem 0 0;
  color: var(--muted, #9fb0c9);
  font-size: .82rem;
  line-height: 1.42;
}

.rfc-diagram-scroll {
  overflow-x: auto;
  padding: 1rem;
}

.rfc-diagram-panel pre {
  width: max-content;
  min-width: 100%;
  margin: 0;
  padding: 1rem;
  border-radius: .95rem;
  border: 1px solid rgba(255,255,255,.08);
  background: rgba(0,0,0,.18);
  color: #eaf4ff;
  font: .98rem/1.55 "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  white-space: pre;
  tab-size: 4;
}

.rfc-diagram-svg,
.rfc-header-svg {
  max-width: 100%;
  height: auto;
}

.rfc-diagram-source {
  margin: .75rem 1rem 1rem;
  color: var(--muted, #9fb0c9);
  font-size: .9rem;
}

.rfc-diagram-source summary {
  cursor: pointer;
  user-select: none;
}

.rfc-diagram-source pre {
  overflow-x: auto;
  padding: .8rem;
  border-radius: .75rem;
  background: rgba(255,255,255,.055);
}

@media (max-width: 720px) {
  .packet-field-grid {
    display: grid;
    grid-template-columns: 1fr;
  }
  .packet-field {
    min-width: 0;
  }
  .rfc-diagram-panel pre {
    font-size: .86rem;
  }
}
"""
