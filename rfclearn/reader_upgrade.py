"""Final reader renderer for generated RFC pages.

The original builder preserves RFC Editor pages as individual source cards. That
keeps page breaks, but it leaks cover pages, jump-link placeholders, notes,
page badges, and accidental headings. This module runs last and rebuilds each
RFC page from cached RFC text as a clean continuous reader.
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

from .config import DATA_DIR, SITE_DIR, RFCS, HEADER_REFERENCES
from .diagram_upgrade import KNOWN_FLOW_FIGURES, flow_figure, render_ascii_diagram_panel, render_header_layout_svg

NORMATIVE_RE = re.compile(r"\b(MUST NOT|SHOULD NOT|MUST|SHOULD|MAY|REQUIRED|RECOMMENDED|OPTIONAL)\b")
RFC_FILE_RE = re.compile(r"rfc(?P<num>\d+)\.html$", re.I)
TITLE_BY_NUM = {meta.num: meta.title for meta in RFCS}
SUMMARY_BY_NUM = {meta.num: meta.relevance for meta in RFCS}


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:80] or "section"


def _rfc_num_from_path(path: Path) -> int | None:
    match = RFC_FILE_RE.search(path.name)
    return int(match.group("num")) if match else None


def _read_rfc_text(rfc_num: int) -> str:
    path = DATA_DIR / "txt" / f"rfc{rfc_num}.txt"
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def _is_page_artifact(line: str) -> bool:
    clean = line.strip()
    if not clean:
        return False
    if "[Page " in clean or re.fullmatch(r"\[?[Pp]age\s+\d+\]?", clean):
        return True
    if re.match(r"^(Network Working Group|Request for Comments|Category:|Updates:|Obsoletes:)\b", clean, re.I):
        return True
    if re.fullmatch(r"[-_\s]{8,}", clean):
        return True
    return False


def _start_index(lines: list[str]) -> int:
    candidates: list[int] = []
    for idx, line in enumerate(lines[:240]):
        clean = line.strip()
        if re.fullmatch(r"(?:Abstract|Status of This Memo|Status of this Memo)", clean, re.I):
            candidates.append(idx)
        elif re.match(r"^1\.?\s+Introduction\b", clean, re.I):
            candidates.append(idx)
        elif re.match(r"^1\.?\s+[A-Z][A-Za-z ]{3,}$", clean) and idx > 20:
            candidates.append(idx)
    return min(candidates) if candidates else 0


def _clean_lines(text: str) -> list[str]:
    raw_lines = text.replace("\ufeff", "").replace("\r", "").replace("\f", "\n").splitlines()
    lines = raw_lines[_start_index(raw_lines):]
    cleaned: list[str] = []
    blank_run = 0
    for line in lines:
        if _is_page_artifact(line):
            continue
        if not line.strip():
            blank_run += 1
            if blank_run <= 2:
                cleaned.append("")
            continue
        blank_run = 0
        cleaned.append(line.rstrip())
    return cleaned


def _blocks_from_lines(lines: list[str]) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    for line in lines:
        if line.strip():
            current.append(line)
        else:
            if current:
                blocks.append("\n".join(current))
                current = []
    if current:
        blocks.append("\n".join(current))
    return blocks


def _looks_like_real_diagram(block: str) -> bool:
    lines = [line for line in block.splitlines() if line.strip()]
    if len(lines) < 3 or len(block.strip()) < 90:
        return False
    if all(line.strip().endswith(":") for line in lines):
        return False
    structural = sum(1 for line in lines if re.search(r"\+[-=]{3,}\+|\|.*\||[-=]{8,}|-->|<--", line))
    diagram_chars = sum(ch in "+-|_:/\\<>[]{}=*~^`" for ch in block)
    return structural >= 2 and (diagram_chars / max(len(block), 1)) >= 0.08


def _heading_from_line(line: str) -> tuple[int, str] | None:
    clean = re.sub(r"\s+", " ", line.strip())
    if not clean or len(clean) > 92:
        return None
    lower = clean.lower()
    if any(bad in lower for bad in (
        "occupies only", "confidential", "restricted", "secret", "efto", "mmmm", "prog",
        "class number length description", "compartmentation", "handling restriction",
    )):
        return None
    if re.fullmatch(r"[01]{4,}(?:\s+[01]{4,})*(?:\s*-\s*\w+)?", clean):
        return None
    if re.fullmatch(r"[\\/|+\-_=\s]+", clean):
        return None
    match = re.match(r"^(?P<num>\d+(?:\.\d+)*)(?:\.)?\s+(?P<title>[A-Za-z][A-Za-z0-9 ,;:/()'\-]{2,70})$", clean)
    if match:
        num = match.group("num")
        title = match.group("title").strip()
        level = 2 + min(num.count("."), 2)
        return level, f"{num}. {title.title() if title.isupper() else title}"
    if re.fullmatch(r"(?:Abstract|Status of This Memo|Security Considerations|References|Acknowledgements|Acknowledgments|Appendix [A-Z])", clean, re.I):
        return 2, clean.title() if clean.isupper() else clean
    return None


def _mark_text(text: str) -> str:
    escaped = html.escape(re.sub(r"\s+", " ", text).strip())
    escaped = NORMATIVE_RE.sub(r'<span class="normative-keyword">\1</span>', escaped)
    escaped = re.sub(r"\bRFC\s+(\d{3,5})\b", r'<span class="rfc-inline-ref">RFC \1</span>', escaped)
    escaped = re.sub(r"\[(\d+)\]", r'<span class="citation-ref">[\1]</span>', escaped)
    return escaped


def _flush_para(parts: list[str], output: list[str]) -> None:
    if not parts:
        return
    text = " ".join(part.strip() for part in parts).strip()
    if text:
        output.append(f"<p>{_mark_text(text)}</p>")
    parts.clear()


def _render_body(lines: list[str]) -> tuple[str, list[tuple[int, str, str]]]:
    output: list[str] = []
    toc: list[tuple[int, str, str]] = []
    para: list[str] = []
    seen_ids: dict[str, int] = {}

    for block in _blocks_from_lines(lines):
        block_lines = block.splitlines()
        if _looks_like_real_diagram(block):
            _flush_para(para, output)
            output.append(render_ascii_diagram_panel(block, title="Original RFC diagram"))
            continue

        heading = _heading_from_line(block_lines[0]) if block_lines else None
        if heading:
            _flush_para(para, output)
            level, label = heading
            base = _slugify(label)
            count = seen_ids.get(base, 0)
            seen_ids[base] = count + 1
            ident = base if count == 0 else f"{base}-{count + 1}"
            toc.append((level, ident, label))
            output.append(f'<h{level} id="{ident}" class="rfc-clean-heading"><span>{html.escape(label)}</span></h{level}>')
            rest = "\n".join(block_lines[1:]).strip()
            if rest:
                para.append(rest)
            continue

        if len(block_lines) >= 2 and any(re.search(r"\s{3,}|\t|\|", line) for line in block_lines):
            _flush_para(para, output)
            output.append(f'<pre class="rfc-readable-pre rfc-tableish">{html.escape(block)}</pre>')
            continue

        para.append(block)

    _flush_para(para, output)
    return "\n".join(output), toc


def _render_toc(toc: list[tuple[int, str, str]]) -> str:
    if not toc:
        return ""
    links = []
    for level, ident, label in toc[:60]:
        child = " child" if level > 2 else ""
        links.append(f'<a class="reader-toc-link level-{level}{child}" href="#{html.escape(ident)}">{html.escape(label)}</a>')
    return '<aside class="reader-toc"><div class="reader-toc-title">On this RFC</div><nav>' + "".join(links) + "</nav></aside>"


def _visuals(rfc_num: int) -> str:
    pieces: list[str] = []
    if rfc_num in HEADER_REFERENCES:
        pieces.append(render_header_layout_svg(HEADER_REFERENCES[rfc_num]))
    flows = [flow_figure(title, steps, ident=ident) for title, steps, ident in KNOWN_FLOW_FIGURES.get(rfc_num, [])]
    if flows:
        pieces.append('<section class="protocol-figure-deck" aria-label="Protocol visual summaries">' + "\n".join(flows) + "</section>")
    return "\n".join(piece for piece in pieces if piece)


def _render_page(rfc_num: int, title: str, body_html: str, toc: list[tuple[int, str, str]]) -> str:
    summary = SUMMARY_BY_NUM.get(rfc_num, "")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RFC {rfc_num}: {html.escape(title)}</title>
  <link rel="stylesheet" href="../assets/site.css">
  <link rel="stylesheet" href="../assets/diagram-upgrades.css">
  <link rel="stylesheet" href="../assets/reader-upgrades.css">
  <script defer src="../assets/reader-upgrades.js"></script>
</head>
<body class="reader-upgraded reader-mode-comfortable">
  <div class="reader-palette" aria-label="Reader display controls">
    <div class="reader-palette-title">RFC {rfc_num}: {html.escape(title)}</div>
    <div class="reader-palette-actions">
      <button type="button" data-reader-mode="comfortable">Comfort</button>
      <button type="button" data-reader-mode="dense">Dense</button>
      <button type="button" data-reader-mode="wide">Wide</button>
      <button type="button" data-reader-mode="focus">Focus</button>
    </div>
  </div>
  <div class="doc-layout clean-doc-layout">
    {_render_toc(toc)}
    <main class="doc-body rfc-clean-reader">
      <header class="rfc-clean-hero">
        <a class="back-link" href="../index.html">← RFC Library</a>
        <p class="eyebrow">RFC {rfc_num}</p>
        <h1>{html.escape(title)}</h1>
        {f'<p class="hero-summary">{html.escape(summary)}</p>' if summary else ''}
      </header>
      {_visuals(rfc_num)}
      <article class="rfc-prose">{body_html}</article>
    </main>
  </div>
</body>
</html>
"""


def _rebuild_rfc_page(path: Path) -> bool:
    rfc_num = _rfc_num_from_path(path)
    if not rfc_num:
        return False
    text = _read_rfc_text(rfc_num)
    if not text:
        return False
    body_html, toc = _render_body(_clean_lines(text))
    title = TITLE_BY_NUM.get(rfc_num, f"RFC {rfc_num}")
    new_page = _render_page(rfc_num, title, body_html, toc)
    old_page = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    if old_page != new_page:
        path.write_text(new_page, encoding="utf-8")
        return True
    return False


def write_reader_assets(asset_dir: Path) -> None:
    asset_dir.mkdir(parents=True, exist_ok=True)
    (asset_dir / "reader-upgrades.css").write_text(READER_CSS.strip() + "\n", encoding="utf-8")
    (asset_dir / "reader-upgrades.js").write_text(READER_JS.strip() + "\n", encoding="utf-8")


def postprocess_site(site_dir: Path = SITE_DIR) -> int:
    rfc_dir = site_dir / "rfc"
    if not rfc_dir.exists():
        return 0
    write_reader_assets(site_dir / "assets")
    changed = 0
    for path in sorted(rfc_dir.glob("*.html")):
        changed += int(_rebuild_rfc_page(path))
    return changed


def install_reader_upgrade(builder_module: Any) -> None:
    original_main = builder_module.main
    def main_with_reader_upgrade(*args: Any, **kwargs: Any) -> Any:
        result = original_main(*args, **kwargs)
        postprocess_site()
        return result
    builder_module.main = main_with_reader_upgrade


READER_CSS = r"""
:root { --reader-measure: 78ch; --reader-wide: 116ch; }
.reader-palette { position: sticky; top: 0; z-index: 50; display: flex; justify-content: space-between; align-items: center; gap: 1rem; width: min(1160px, calc(100% - 32px)); margin: 0 auto; padding: .72rem 1rem; border: 1px solid rgba(255,255,255,.12); border-top: 0; border-radius: 0 0 1.1rem 1.1rem; background: rgba(7,9,18,.88); backdrop-filter: blur(18px) saturate(1.25); box-shadow: 0 14px 48px rgba(0,0,0,.32); }
.reader-palette-title { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted, #9fb0c9); font-size: .84rem; font-weight: 850; }
.reader-palette-actions { display: flex; flex-wrap: wrap; gap: .45rem; }
.reader-palette button { border: 1px solid rgba(255,255,255,.14); border-radius: 999px; padding: .38rem .7rem; color: var(--text, #eef5ff); background: rgba(255,255,255,.055); font: inherit; font-size: .76rem; font-weight: 850; cursor: pointer; }
.reader-palette button:hover, .reader-palette button.active { border-color: rgba(101,228,255,.55); background: rgba(101,228,255,.16); color: var(--cyan, #65e4ff); }
.clean-doc-layout { width: min(1280px, calc(100% - 28px)); margin: 1.25rem auto 4rem; display: grid; grid-template-columns: minmax(0, 1fr) 17rem; gap: 1.25rem; }
.rfc-clean-reader { max-width: var(--reader-wide); min-width: 0; grid-column: 1; }
.reader-toc { grid-column: 2; grid-row: 1; position: sticky; top: 5.3rem; align-self: start; max-height: calc(100vh - 6rem); overflow: auto; padding: .95rem; border: 1px solid rgba(255,255,255,.11); border-radius: 1.15rem; background: rgba(10,15,28,.84); backdrop-filter: blur(16px); box-shadow: 0 16px 58px rgba(0,0,0,.30); }
.reader-toc-title { margin-bottom: .55rem; color: var(--cyan, #65e4ff); font-size: .74rem; font-weight: 950; letter-spacing: .14em; text-transform: uppercase; }
.reader-toc nav { display: grid; gap: .2rem; }
.reader-toc-link { display: block; padding: .42rem .5rem; border-radius: .75rem; color: var(--muted, #9fb0c9); font-size: .82rem; line-height: 1.25; text-decoration: none !important; }
.reader-toc-link.child { padding-left: 1rem; font-size: .76rem; opacity: .88; }
.reader-toc-link:hover { color: var(--text, #eef5ff); background: rgba(101,228,255,.1); }
.rfc-clean-hero { max-width: var(--reader-measure); margin: 0 auto 1.4rem; padding: 1.2rem 1.35rem; border: 1px solid rgba(101,228,255,.22); border-radius: 1.35rem; background: radial-gradient(circle at top right, rgba(101,228,255,.16), transparent 48%), linear-gradient(145deg, rgba(19,28,48,.92), rgba(8,12,23,.82)); }
.back-link { color: var(--cyan, #65e4ff); text-decoration: none; font-weight: 850; font-size: .86rem; }
.eyebrow { margin: .8rem 0 .2rem; color: var(--cyan, #65e4ff); font-size: .78rem; letter-spacing: .16em; font-weight: 950; text-transform: uppercase; }
.rfc-clean-hero h1 { margin: 0; font-size: clamp(1.8rem, 4vw, 3.4rem); line-height: 1.02; letter-spacing: -.045em; }
.hero-summary { color: var(--muted, #9fb0c9); max-width: 70ch; }
.rfc-prose { max-width: var(--reader-measure); margin: 0 auto; color: #dce8f8; font: 1.03rem/1.78 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
.rfc-prose p { margin: .95rem 0; text-wrap: pretty; }
.rfc-clean-heading { scroll-margin-top: 6rem; margin: 2.25rem 0 .85rem; padding-bottom: .5rem; border-bottom: 1px solid rgba(101,228,255,.20); color: var(--cyan, #65e4ff); letter-spacing: -.02em; }
.rfc-clean-heading + p { margin-top: .4rem; }
.rfc-readable-pre { max-width: var(--reader-measure); margin: 1.1rem auto !important; padding: .85rem 1rem !important; border: 1px solid rgba(255,255,255,.10) !important; border-radius: 1rem !important; background: rgba(255,255,255,.028) !important; color: #dce8f8 !important; font: .95rem/1.65 "IBM Plex Mono", "SFMono-Regular", Consolas, monospace !important; white-space: pre-wrap !important; overflow-x: auto; tab-size: 4; }
.rfc-tableish { white-space: pre !important; }
.normative-keyword { display: inline-block; padding: .02rem .28rem; border-radius: .38rem; color: #ffe2a0; background: rgba(255,211,106,.13); font-weight: 900; letter-spacing: .02em; }
.citation-ref, .rfc-inline-ref { display: inline-flex; border-radius: .45rem; padding: .02rem .32rem; color: var(--cyan, #65e4ff); background: rgba(101,228,255,.09); font-weight: 800; }
.rfc-inline-ref { color: var(--green, #7dffa8); background: rgba(125,255,168,.08); }
body.reader-mode-focus .reader-toc, body.reader-mode-focus .protocol-figure-deck, body.reader-mode-focus .rfc-header-panel { display: none; }
body.reader-mode-focus .clean-doc-layout, body.reader-mode-comfortable .clean-doc-layout { grid-template-columns: minmax(0, 1fr); }
body.reader-mode-focus .rfc-clean-reader, body.reader-mode-comfortable .rfc-clean-reader { max-width: var(--reader-measure); margin-inline: auto; }
body.reader-mode-focus .reader-toc, body.reader-mode-comfortable .reader-toc { display: none; }
body.reader-mode-wide .rfc-prose, body.reader-mode-wide .rfc-clean-hero { max-width: var(--reader-wide); }
body.reader-mode-dense .rfc-prose { font-size: .94rem; line-height: 1.58; }
body.reader-mode-dense .rfc-prose p { margin: .55rem 0; }
textarea, button.note-btn, .note-status, .section-note, .inline-note, [class*="note"], [id*="note"] { display: none !important; }
@media (max-width: 980px) { .clean-doc-layout { grid-template-columns: 1fr; } .reader-toc { display: none; } .reader-palette { position: static; border-radius: 0 0 1rem 1rem; } .reader-palette-title { display: none; } }
@media print { .reader-palette, .reader-toc, .protocol-figure-deck, .rfc-header-panel { display: none !important; } .clean-doc-layout { display: block; width: 100%; } }
"""


READER_JS = r"""
(function () {
  const modes = ["comfortable", "dense", "wide", "focus"];
  const storageKey = "rfclearn.readerMode";
  function setMode(mode) {
    if (!modes.includes(mode)) mode = "comfortable";
    document.body.classList.remove(...modes.map((m) => `reader-mode-${m}`));
    document.body.classList.add(`reader-mode-${mode}`);
    localStorage.setItem(storageKey, mode);
    document.querySelectorAll("[data-reader-mode]").forEach((button) => {
      button.classList.toggle("active", button.dataset.readerMode === mode);
    });
  }
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-reader-mode]");
    if (!button) return;
    setMode(button.dataset.readerMode);
  });
  setMode(localStorage.getItem(storageKey) || "comfortable");
})();
"""
