"""Reader-experience upgrades for generated RFC pages.

This layer fixes the real readability problem with RFCs: generated pages often
preserve the source as fixed-width plaintext. That keeps the archive honest, but
it is miserable for sustained reading. The postprocessor below converts prose
blocks into semantic article HTML, suppresses page-artifact noise, preserves
true code/diagrams, and adds a small reader UI.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import SITE_DIR

ASSET_HREF = "../assets/reader-upgrades.css"
SCRIPT_HREF = "../assets/reader-upgrades.js"
BODY_RE = re.compile(r"<body(?P<attrs>[^>]*)>", flags=re.IGNORECASE)
TITLE_RE = re.compile(r"<title>(?P<title>.*?)</title>", flags=re.IGNORECASE | re.DOTALL)
HEADING_RE = re.compile(r"<h(?P<level>[123])(?P<attrs>[^>]*)>(?P<body>.*?)</h(?P=level)>", flags=re.IGNORECASE | re.DOTALL)
PRE_RE = re.compile(r"<pre(?P<attrs>[^>]*)>(?P<body>.*?)</pre>", flags=re.IGNORECASE | re.DOTALL)
PAGE_FOOTER_RE = re.compile(r"^\s*(?:[A-Z][A-Za-z-]+\s+)?(?:RFC\s+\d+|\[[Pp]age\s+\d+\]|[A-Za-z]+\s+\d{4})\s*$")
PAGE_HEADER_RE = re.compile(r"^\s*(?:Network Working Group|Request for Comments|Category:|Updates:|Obsoletes:|Internet Engineering Task Force)\b", re.I)
SECTION_RE = re.compile(r"^\s*(?P<num>\d+(?:\.\d+)*\.?)(?:\s+|\t+)(?P<title>[A-Z][A-Za-z0-9 ,:;()/\-']{2,})\s*$")
NORMATIVE_RE = re.compile(r"\b(MUST NOT|SHOULD NOT|MUST|SHOULD|MAY|REQUIRED|RECOMMENDED|OPTIONAL)\b")


@dataclass(frozen=True)
class TocItem:
    level: int
    ident: str
    label: str


def _strip_tags(value: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", " ", value)).strip()


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:72] or "section"


def _ensure_head_asset(document: str, asset: str, tag: str) -> str:
    if asset in document:
        return document
    if "</head>" not in document:
        return tag + "\n" + document
    return document.replace("</head>", tag + "\n</head>", 1)


def _add_body_class(document: str, class_name: str) -> str:
    def replace(match: re.Match[str]) -> str:
        attrs = match.group("attrs") or ""
        class_match = re.search(r'class="([^"]*)"', attrs)
        if class_match:
            classes = class_match.group(1).split()
            if class_name not in classes:
                classes.append(class_name)
            attrs = attrs[:class_match.start(1)] + " ".join(classes) + attrs[class_match.end(1):]
        else:
            attrs += f' class="{class_name}"'
        return f"<body{attrs}>"

    return BODY_RE.sub(replace, document, count=1)


def _looks_like_diagram_text(text: str) -> bool:
    if not text.strip():
        return False
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) < 2:
        return False
    diagram_chars = sum(ch in "+-|_:/\\<>[]{}=*~^`" for ch in text)
    density = diagram_chars / max(len(text), 1)
    has_ruling = any(re.search(r"[-=+_]{3,}|\|.*\||\+[-=]+|-->|<--|\+-", line) for line in lines)
    longest = max(len(line) for line in lines)
    return longest >= 16 and density >= .10 and has_ruling


def _is_page_artifact(line: str) -> bool:
    clean = html.unescape(line).strip()
    if not clean:
        return False
    if "[Page " in clean or re.fullmatch(r"\[?[Pp]age\s+\d+\]?", clean):
        return True
    if PAGE_HEADER_RE.match(clean):
        return True
    if PAGE_FOOTER_RE.match(clean):
        return True
    if re.fullmatch(r"[-_\s]{8,}", clean):
        return True
    return False


def _is_boilerplate_line(line: str) -> bool:
    clean = html.unescape(line).strip()
    if not clean:
        return False
    if re.fullmatch(r"DARPA\s+INTERNET\s+PROGRAM", clean, re.I):
        return True
    if re.fullmatch(r"PROTOCOL\s+SPECIFICATION", clean, re.I):
        return True
    if re.fullmatch(r"INTERNET\s+PROTOCOL", clean, re.I):
        return True
    return False


def _paragraphize(lines: list[str]) -> list[str]:
    blocks: list[str] = []
    para: list[str] = []

    def flush_para() -> None:
        nonlocal para
        if para:
            text = " ".join(part.strip() for part in para)
            text = re.sub(r"\s+", " ", text).strip()
            if text:
                blocks.append(f"<p>{_linkify_and_mark(html.escape(text))}</p>")
            para = []

    for raw in lines:
        line = html.unescape(re.sub(r"<[^>]+>", "", raw)).rstrip()
        if _is_page_artifact(line) or _is_boilerplate_line(line):
            continue
        if not line.strip():
            flush_para()
            continue
        if _looks_like_diagram_text(line):
            flush_para()
            blocks.append(f'<pre class="rfc-code-block">{html.escape(line)}</pre>')
            continue
        section = SECTION_RE.match(line)
        if section:
            flush_para()
            label = f"{section.group('num')} {section.group('title').strip().title()}"
            ident = _slugify(label)
            level = 2 if section.group("num").count(".") <= 1 else 3
            blocks.append(f'<h{level} id="{ident}" class="rfc-heading generated-heading"><span>{html.escape(label)}</span><a class="heading-anchor" href="#{ident}">#</a></h{level}>')
            continue
        if re.match(r"^\s{8,}\S", raw) and len(line.strip()) < 90 and not line.strip().endswith((".", ";", ",")):
            flush_para()
            label = line.strip().title()
            ident = _slugify(label)
            blocks.append(f'<h2 id="{ident}" class="rfc-heading generated-heading"><span>{html.escape(label)}</span><a class="heading-anchor" href="#{ident}">#</a></h2>')
            continue
        if re.match(r"^\s*[-*o]\s+", line):
            flush_para()
            item = re.sub(r"^\s*[-*o]\s+", "", line).strip()
            blocks.append(f'<ul class="rfc-list"><li>{_linkify_and_mark(html.escape(item))}</li></ul>')
            continue
        para.append(line)

    flush_para()
    return blocks


def _linkify_and_mark(escaped_text: str) -> str:
    text = re.sub(r"\[(\d+)\]", r'<a class="citation-ref" href="#ref-\1">[\1]</a>', escaped_text)
    text = NORMATIVE_RE.sub(r'<span class="normative-keyword">\1</span>', text)
    text = re.sub(r"\bRFC\s+(\d{3,5})\b", r'<span class="rfc-inline-ref">RFC \1</span>', text)
    return text


def _convert_pre_to_article(match: re.Match[str]) -> str:
    attrs = match.group("attrs") or ""
    body = match.group("body")
    whole = match.group(0)
    if "rfc-diagram-source" in whole or "data-rfclearn-diagram" in whole:
        return whole

    raw = html.unescape(re.sub(r"<[^>]+>", "", body)).replace("\r", "")
    lines = raw.splitlines()
    nonempty = [line for line in lines if line.strip()]
    if not nonempty:
        return ""

    # Keep true diagrams/code blocks monospaced. Convert mostly-prose RFC source.
    diagram_ratio = sum(1 for line in nonempty if _looks_like_diagram_text(line)) / max(len(nonempty), 1)
    sentence_like = sum(1 for line in nonempty if re.search(r"[a-z].*[.!?]$", line.strip()))
    if diagram_ratio > .35 or (len(nonempty) < 8 and sentence_like < 2):
        return f'<pre{_classify_pre(attrs, body)}>{body}</pre>'

    blocks = _paragraphize(lines)
    if not blocks:
        return ""
    return '<section class="rfc-readable-source">' + "\n".join(blocks) + '</section>'


def _upgrade_headings(document: str) -> tuple[str, list[TocItem]]:
    seen: dict[str, int] = {}
    toc: list[TocItem] = []

    def replace(match: re.Match[str]) -> str:
        level = int(match.group("level"))
        attrs = match.group("attrs") or ""
        body = match.group("body")
        label = _strip_tags(body)
        if not label:
            return match.group(0)

        existing = re.search(r'id="([^"]+)"', attrs)
        if existing:
            ident = existing.group(1)
        else:
            base = _slugify(label)
            count = seen.get(base, 0)
            seen[base] = count + 1
            ident = base if count == 0 else f"{base}-{count + 1}"
            attrs += f' id="{ident}"'

        if level <= 3:
            toc.append(TocItem(level=level, ident=ident, label=label))

        if "rfc-heading" not in attrs:
            if 'class="' in attrs:
                attrs = re.sub(r'class="([^"]*)"', lambda m: f'class="{m.group(1)} rfc-heading"', attrs, count=1)
            else:
                attrs += ' class="rfc-heading"'

        anchor = "" if "heading-anchor" in body else f'<a class="heading-anchor" href="#{ident}" aria-label="Link to {html.escape(label)}">#</a>'
        return f'<h{level}{attrs}><span>{body}</span>{anchor}</h{level}>'

    return HEADING_RE.sub(replace, document), toc


def _collect_toc_from_document(document: str) -> list[TocItem]:
    toc: list[TocItem] = []
    for match in HEADING_RE.finditer(document):
        level = int(match.group("level"))
        if level > 3:
            continue
        ident_match = re.search(r'id="([^"]+)"', match.group("attrs") or "")
        if not ident_match:
            continue
        label = _strip_tags(match.group("body"))
        if label and label.lower() not in {"readable rfc mode"}:
            toc.append(TocItem(level=level, ident=ident_match.group(1), label=label))
    return toc


def _build_toc(toc: list[TocItem]) -> str:
    if not toc:
        return ""
    items = []
    for item in toc[:42]:
        indent = " child" if item.level > 2 else ""
        items.append(f'<a class="reader-toc-link level-{item.level}{indent}" href="#{html.escape(item.ident)}">{html.escape(item.label)}</a>')
    return '<aside class="reader-toc" aria-label="RFC page navigation"><div class="reader-toc-title">On this RFC</div><nav>' + "".join(items) + '</nav></aside>'


def _insert_toc(document: str, toc: list[TocItem]) -> str:
    if "reader-toc" in document:
        return document
    toc_html = _build_toc(toc)
    if not toc_html:
        return document
    if '<div class="reader-grid"' in document:
        return document.replace('<div class="reader-grid"', toc_html + '\n<div class="reader-grid"', 1)
    for marker in ('<main class="doc-body"', '<article class="doc-body"', '<section class="reader-source-card"'):
        idx = document.find(marker)
        if idx != -1:
            return document[:idx] + toc_html + "\n" + document[idx:]
    return document


def _classify_pre(attrs: str, body: str) -> str:
    raw = _strip_tags(body)
    lines = [line for line in raw.splitlines() if line.strip()]
    classes = ["rfc-pretty-pre"]
    if any(_is_page_artifact(line) for line in lines[:5] + lines[-5:]):
        classes.append("page-artifact")
    if len(lines) > 80:
        classes.append("long-source")
    if re.search(r"\b(MUST|MUST NOT|SHOULD|SHOULD NOT|MAY|REQUIRED|OPTIONAL)\b", raw):
        classes.append("normative-heavy")
    class_text = " ".join(classes)
    if 'class="' in attrs:
        return re.sub(r'class="([^"]*)"', lambda m: f'class="{m.group(1)} {class_text}"', attrs, count=1)
    return attrs + f' class="{class_text}"'


def _upgrade_pre_blocks(document: str) -> str:
    return PRE_RE.sub(_convert_pre_to_article, document)


def _add_reader_palette(document: str) -> str:
    if "reader-palette" in document:
        return document
    title = "RFC Reader"
    title_match = TITLE_RE.search(document)
    if title_match:
        title = _strip_tags(title_match.group("title")) or title
    palette = f"""
<div class="reader-palette" aria-label="Reader display controls">
  <div class="reader-palette-title">{html.escape(title)}</div>
  <div class="reader-palette-actions">
    <button type="button" data-reader-mode="comfortable">Comfort</button>
    <button type="button" data-reader-mode="dense">Dense</button>
    <button type="button" data-reader-mode="wide">Wide</button>
    <button type="button" data-reader-mode="focus">Focus</button>
  </div>
</div>
""".strip()
    if '<div class="doc-layout"' in document:
        return document.replace('<div class="doc-layout"', palette + '\n<div class="doc-layout"', 1)
    if '<main' in document:
        return document.replace('<main', palette + '\n<main', 1)
    return document.replace("<body", "<body", 1).replace(">", ">" + palette, 1)


def _add_source_summary_card(document: str) -> str:
    if "reader-source-card" in document:
        return document
    match = TITLE_RE.search(document)
    title = _strip_tags(match.group("title")) if match else "RFC"
    card = f"""
<section class="reader-source-card">
  <div>
    <span class="reader-source-kicker">Readable RFC Mode</span>
    <h2>{html.escape(title)}</h2>
    <p>Plaintext RFC source is converted into article-style sections. Page headers, blank pages, and footer artifacts are suppressed; diagrams stay visual.</p>
  </div>
</section>
""".strip()
    for marker in ('<article class="doc-body', '<main class="doc-body'):
        idx = document.find(marker)
        if idx != -1:
            return document[:idx] + card + "\n" + document[idx:]
    return document


def _hide_inline_note_widgets(document: str) -> str:
    # The old note widgets interrupt the text in generated pages. Keep them out of
    # the reading flow; a later pass can reintroduce side notes cleanly.
    document = re.sub(r'<textarea[^>]*placeholder="Add your notes for this section\.\.\.".*?</textarea>', '', document, flags=re.I | re.S)
    document = re.sub(r'<button[^>]*>\s*Note\s*</button>', '', document, flags=re.I)
    document = re.sub(r'<div[^>]*>\s*Saved\s*</div>', '', document, flags=re.I)
    return document


def upgrade_document(document: str) -> str:
    document = _ensure_head_asset(document, ASSET_HREF, f'<link rel="stylesheet" href="{ASSET_HREF}">')
    document = _ensure_head_asset(document, SCRIPT_HREF, f'<script defer src="{SCRIPT_HREF}"></script>')
    document = _add_body_class(document, "reader-upgraded")
    document = _hide_inline_note_widgets(document)
    document = _upgrade_pre_blocks(document)
    document, _ = _upgrade_headings(document)
    toc = _collect_toc_from_document(document)
    document = _add_source_summary_card(document)
    document = _insert_toc(document, toc)
    document = _add_reader_palette(document)
    return document


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
        original = path.read_text(encoding="utf-8", errors="replace")
        upgraded = upgrade_document(original)
        if upgraded != original:
            path.write_text(upgraded, encoding="utf-8")
            changed += 1
    return changed


def install_reader_upgrade(builder_module: Any) -> None:
    original_main = builder_module.main

    def main_with_reader_upgrade(*args: Any, **kwargs: Any) -> Any:
        result = original_main(*args, **kwargs)
        postprocess_site()
        return result

    builder_module.main = main_with_reader_upgrade


READER_CSS = r"""
:root {
  --reader-measure: 74ch;
  --reader-wide: 112ch;
  --reader-card: rgba(13, 19, 34, 0.94);
}

body.reader-upgraded {
  --reading-shadow: 0 22px 80px rgba(0,0,0,.38);
}

.reader-palette {
  position: sticky;
  top: 0;
  z-index: 50;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
  width: min(1160px, calc(100% - 32px));
  margin: 0 auto;
  padding: .78rem 1rem;
  border: 1px solid var(--line, rgba(255,255,255,.12));
  border-top: 0;
  border-radius: 0 0 1.25rem 1.25rem;
  background: rgba(7,9,18,.88);
  backdrop-filter: blur(18px) saturate(1.25);
  box-shadow: 0 14px 48px rgba(0,0,0,.32);
}

.reader-palette-title {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--muted, #9fb0c9);
  font-size: .86rem;
  font-weight: 850;
  letter-spacing: .04em;
}

.reader-palette-actions { display: flex; flex-wrap: wrap; gap: .45rem; }
.reader-palette button {
  border: 1px solid rgba(255,255,255,.14);
  border-radius: 999px;
  padding: .42rem .72rem;
  color: var(--text, #eef5ff);
  background: rgba(255,255,255,.055);
  font: inherit;
  font-size: .78rem;
  font-weight: 850;
  cursor: pointer;
}
.reader-palette button:hover,
.reader-palette button.active {
  border-color: rgba(101,228,255,.55);
  background: rgba(101,228,255,.16);
  color: var(--cyan, #65e4ff);
}

.reader-source-card {
  max-width: var(--reader-wide);
  margin: 0 auto 1rem;
  padding: 1.1rem 1.3rem;
  border: 1px solid rgba(101,228,255,.22);
  border-radius: 1.35rem;
  background: radial-gradient(circle at top right, rgba(101,228,255,.16), transparent 48%), linear-gradient(145deg, rgba(19,28,48,.92), rgba(8,12,23,.82));
  box-shadow: var(--reading-shadow);
}
.reader-source-kicker {
  display: inline-flex;
  width: fit-content;
  margin-bottom: .42rem;
  border-radius: 999px;
  padding: .26rem .65rem;
  color: var(--cyan, #65e4ff);
  background: rgba(101,228,255,.1);
  border: 1px solid rgba(101,228,255,.22);
  font-size: .72rem;
  font-weight: 900;
  letter-spacing: .16em;
  text-transform: uppercase;
}
.reader-source-card h2 { margin: 0; font-size: clamp(1.2rem, 2vw, 1.8rem); letter-spacing: -.03em; }
.reader-source-card p { max-width: 72ch; margin: .2rem 0 0; color: var(--muted, #9fb0c9); }

.reader-toc {
  position: sticky;
  top: 5.3rem;
  z-index: 4;
  float: right;
  width: 17rem;
  max-height: calc(100vh - 6.4rem);
  overflow: auto;
  margin: 0 0 1rem 1rem;
  padding: .95rem;
  border: 1px solid rgba(255,255,255,.11);
  border-radius: 1.15rem;
  background: rgba(10,15,28,.84);
  backdrop-filter: blur(16px);
  box-shadow: 0 16px 58px rgba(0,0,0,.30);
}
.reader-toc-title { margin-bottom: .55rem; color: var(--cyan, #65e4ff); font-size: .74rem; font-weight: 950; letter-spacing: .14em; text-transform: uppercase; }
.reader-toc nav { display: grid; gap: .2rem; }
.reader-toc-link { display: block; padding: .42rem .5rem; border-radius: .75rem; color: var(--muted, #9fb0c9); font-size: .82rem; line-height: 1.25; text-decoration: none !important; }
.reader-toc-link.child { padding-left: 1rem; font-size: .76rem; opacity: .88; }
.reader-toc-link:hover, .reader-toc-link.active { color: var(--text, #eef5ff); background: rgba(101,228,255,.1); }

.doc-body {
  max-width: var(--reader-wide) !important;
  margin-inline: auto;
  padding: clamp(1.25rem, 3vw, 3rem) !important;
}
body.reader-mode-focus .doc-body,
body.reader-mode-comfortable .rfc-readable-source {
  max-width: var(--reader-measure);
}
body.reader-mode-wide .doc-body,
body.reader-mode-wide .rfc-readable-source { max-width: min(1180px, calc(100vw - 2rem)); }
body.reader-mode-dense .doc-body { padding: 1.4rem 1.6rem !important; }
body.reader-mode-dense .rfc-readable-source p { margin-block: .55rem; line-height: 1.58; }
body.reader-mode-focus .reader-toc,
body.reader-mode-focus .reader-source-card { display: none; }
body.reader-mode-focus .reader-palette { opacity: .78; }

.rfc-readable-source {
  max-width: var(--reader-measure);
  margin: 0 auto;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 1.04rem;
  line-height: 1.78;
  color: #e7f0ff;
}

.rfc-readable-source p {
  margin: .95rem 0;
  max-width: var(--reader-measure);
  text-wrap: pretty;
}

.rfc-readable-source p:first-of-type { margin-top: 0; }

.generated-heading,
.rfc-heading {
  scroll-margin-top: 6.5rem;
  display: flex;
  align-items: baseline;
  gap: .5rem;
}
.generated-heading {
  margin: 2.35rem 0 .9rem !important;
  padding-bottom: .55rem;
  border-bottom: 1px solid rgba(101,228,255,.20);
}
.generated-heading span { color: var(--cyan, #65e4ff); }
.rfc-heading .heading-anchor { opacity: 0; flex: none; color: var(--cyan, #65e4ff) !important; text-decoration: none !important; font-size: .75em; transition: opacity .18s ease, transform .18s ease; }
.rfc-heading:hover .heading-anchor { opacity: .85; transform: translateX(.1rem); }

.citation-ref,
.rfc-inline-ref {
  display: inline-flex;
  align-items: center;
  border-radius: .45rem;
  padding: .02rem .32rem;
  color: var(--cyan, #65e4ff) !important;
  background: rgba(101,228,255,.09);
  text-decoration: none !important;
  font-weight: 800;
}
.rfc-inline-ref { color: var(--green, #7dffa8) !important; background: rgba(125,255,168,.08); }

.normative-keyword {
  display: inline-block;
  padding: .02rem .28rem;
  border-radius: .38rem;
  color: #ffe2a0;
  background: rgba(255,211,106,.13);
  font-weight: 900;
  letter-spacing: .02em;
}

.rfc-code-block,
.rfc-pretty-pre {
  position: relative;
  margin: 1.05rem 0 !important;
  padding: 1.05rem 1.1rem !important;
  border: 1px solid rgba(255,255,255,.10);
  border-radius: 1rem !important;
  background: linear-gradient(90deg, rgba(101,228,255,.045), transparent 18rem), rgba(255,255,255,.030) !important;
  color: #edf6ff !important;
  font: .92rem/1.65 "IBM Plex Mono", "SFMono-Regular", Consolas, monospace !important;
  white-space: pre-wrap;
  overflow-x: auto;
  tab-size: 4;
}

.page-artifact { display: none !important; }
.rfc-list { margin: .65rem 0 .65rem 1.1rem; }
.rfc-list + .rfc-list { margin-top: -.45rem; }

.doc-body blockquote { margin: 1.2rem 0; padding: .8rem 1rem; border-left: 4px solid var(--cyan, #65e4ff); border-radius: .85rem; background: rgba(101,228,255,.07); color: var(--text2, #d8e6fa); }
.doc-body hr { border: 0; height: 1px; margin: 2rem 0; background: linear-gradient(90deg, transparent, rgba(101,228,255,.35), transparent); }

/* Hide old inline note controls that were interrupting sections. */
textarea[placeholder="Add your notes for this section..."] { display: none !important; }
button.note-btn,
.note-status,
.section-note,
.inline-note { display: none !important; }

@media (max-width: 980px) {
  .reader-palette { position: static; border-radius: 0 0 1rem 1rem; }
  .reader-toc { position: static; float: none; width: auto; max-height: 14rem; margin: 0 auto 1rem; max-width: var(--reader-measure); }
  .reader-palette-title { display: none; }
}

@media print {
  .reader-palette, .reader-toc, .heading-anchor { display: none !important; }
  .doc-body, .reader-source-card { box-shadow: none !important; border-color: #ddd !important; }
}
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

  const links = Array.from(document.querySelectorAll(".reader-toc-link"));
  const targets = links.map((link) => document.getElementById(link.getAttribute("href").slice(1))).filter(Boolean);

  if ("IntersectionObserver" in window && targets.length) {
    const observer = new IntersectionObserver((entries) => {
      const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (!visible) return;
      links.forEach((link) => {
        link.classList.toggle("active", link.getAttribute("href") === `#${visible.target.id}`);
      });
    }, { rootMargin: "-18% 0px -70% 0px", threshold: [0.1, 0.25, 0.5] });
    targets.forEach((target) => observer.observe(target));
  }
})();
"""
