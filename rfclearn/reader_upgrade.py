"""Reader-experience upgrades for generated RFC pages.

This module is intentionally post-processing oriented. The builder can keep
focusing on RFC collection and content generation while this layer polishes the
HTML output into something that feels like a modern technical reader instead of
a lovingly haunted plaintext archive.
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

        if 'class="' in attrs:
            attrs = re.sub(r'class="([^"]*)"', lambda m: f'class="{m.group(1)} rfc-heading"', attrs, count=1)
        else:
            attrs += ' class="rfc-heading"'

        anchor = f'<a class="heading-anchor" href="#{ident}" aria-label="Link to {html.escape(label)}">#</a>'
        return f'<h{level}{attrs}><span>{body}</span>{anchor}</h{level}>'

    return HEADING_RE.sub(replace, document), toc


def _build_toc(toc: list[TocItem]) -> str:
    if not toc:
        return ""

    items = []
    for item in toc[:34]:
        indent = " child" if item.level > 2 else ""
        items.append(
            f'<a class="reader-toc-link level-{item.level}{indent}" href="#{html.escape(item.ident)}">'
            f'{html.escape(item.label)}</a>'
        )

    return (
        '<aside class="reader-toc" aria-label="RFC page navigation">'
        '<div class="reader-toc-title">On this RFC</div>'
        '<nav>' + "".join(items) + '</nav>'
        '</aside>'
    )


def _insert_toc(document: str, toc: list[TocItem]) -> str:
    if "reader-toc" in document:
        return document
    toc_html = _build_toc(toc)
    if not toc_html:
        return document
    if '<div class="reader-grid"' in document:
        # Prefer the existing side column if the builder already has a reader grid.
        return document.replace('<div class="reader-grid"', toc_html + '\n<div class="reader-grid"', 1)
    if '<main class="doc-body"' in document:
        return document.replace('<main class="doc-body"', toc_html + '\n<main class="doc-body"', 1)
    if '<article class="doc-body"' in document:
        return document.replace('<article class="doc-body"', toc_html + '\n<article class="doc-body"', 1)
    return document


def _classify_pre(attrs: str, body: str) -> str:
    raw = _strip_tags(body)
    lines = [line for line in raw.splitlines() if line.strip()]
    classes = ["rfc-pretty-pre"]
    if any("[Page " in line or re.search(r"\bPage\s+\d+\b", line) for line in lines[:5] + lines[-5:]):
        classes.append("page-artifact")
    if len(lines) > 80:
        classes.append("long-source")
    if any(re.match(r"\s*(Abstract|Status of This Memo|Table of Contents|Introduction)\s*$", line, re.I) for line in lines[:30]):
        classes.append("front-matter")
    if re.search(r"\b(MUST|MUST NOT|SHOULD|SHOULD NOT|MAY|REQUIRED|OPTIONAL)\b", raw):
        classes.append("normative-heavy")
    class_text = " ".join(classes)
    if 'class="' in attrs:
        return re.sub(r'class="([^"]*)"', lambda m: f'class="{m.group(1)} {class_text}"', attrs, count=1)
    return attrs + f' class="{class_text}"'


def _upgrade_pre_blocks(document: str) -> str:
    def replace(match: re.Match[str]) -> str:
        attrs = match.group("attrs") or ""
        body = match.group("body")
        if "rfc-diagram-source" in attrs or "rfc-diagram-source" in match.group(0):
            return match.group(0)
        return f'<pre{_classify_pre(attrs, body)}>{body}</pre>'

    return PRE_RE.sub(replace, document)


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


def _highlight_normative_terms(document: str) -> str:
    # Avoid touching attributes by only working inside pre/code-ish text blocks after escaping is already done.
    def replace_pre(match: re.Match[str]) -> str:
        attrs = match.group("attrs") or ""
        body = match.group("body")
        body = re.sub(
            r"\b(MUST NOT|SHOULD NOT|MUST|SHOULD|MAY|REQUIRED|RECOMMENDED|OPTIONAL)\b",
            r'<span class="normative-keyword">\1</span>',
            body,
        )
        return f"<pre{attrs}>{body}</pre>"

    return PRE_RE.sub(replace_pre, document)


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
    <p>Sections, diagrams, page artifacts, and normative language are styled for scanning first and close reading second.</p>
  </div>
</section>
""".strip()
    for marker in ('<article class="doc-body', '<main class="doc-body'):
        idx = document.find(marker)
        if idx != -1:
            return document[:idx] + card + "\n" + document[idx:]
    return document


def upgrade_document(document: str) -> str:
    document = _ensure_head_asset(
        document,
        ASSET_HREF,
        f'<link rel="stylesheet" href="{ASSET_HREF}">',
    )
    document = _ensure_head_asset(
        document,
        SCRIPT_HREF,
        f'<script defer src="{SCRIPT_HREF}"></script>',
    )
    document = _add_body_class(document, "reader-upgraded")
    document, toc = _upgrade_headings(document)
    document = _add_source_summary_card(document)
    document = _insert_toc(document, toc)
    document = _upgrade_pre_blocks(document)
    document = _highlight_normative_terms(document)
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
  --reader-measure: 76ch;
  --reader-pre-measure: 108ch;
  --reader-card: rgba(13, 19, 34, 0.92);
  --reader-card-2: rgba(19, 28, 48, 0.84);
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
  background: rgba(7,9,18,.86);
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

.reader-palette-actions {
  display: flex;
  flex-wrap: wrap;
  gap: .45rem;
}

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
  display: grid;
  gap: .35rem;
  margin: 0 0 1rem;
  padding: 1.2rem 1.35rem;
  border: 1px solid rgba(101,228,255,.22);
  border-radius: 1.35rem;
  background:
    radial-gradient(circle at top right, rgba(101,228,255,.16), transparent 48%),
    linear-gradient(145deg, rgba(19,28,48,.92), rgba(8,12,23,.82));
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

.reader-source-card h2 {
  margin: 0;
  font-size: clamp(1.2rem, 2vw, 1.8rem);
  letter-spacing: -.03em;
}

.reader-source-card p {
  max-width: 72ch;
  margin: .2rem 0 0;
  color: var(--muted, #9fb0c9);
}

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
  background: rgba(10,15,28,.82);
  backdrop-filter: blur(16px);
  box-shadow: 0 16px 58px rgba(0,0,0,.30);
}

.reader-toc-title {
  margin-bottom: .55rem;
  color: var(--cyan, #65e4ff);
  font-size: .74rem;
  font-weight: 950;
  letter-spacing: .14em;
  text-transform: uppercase;
}

.reader-toc nav {
  display: grid;
  gap: .2rem;
}

.reader-toc-link {
  display: block;
  padding: .42rem .5rem;
  border-radius: .75rem;
  color: var(--muted, #9fb0c9);
  font-size: .82rem;
  line-height: 1.25;
  text-decoration: none !important;
}

.reader-toc-link.child {
  padding-left: 1rem;
  font-size: .76rem;
  opacity: .88;
}

.reader-toc-link:hover,
.reader-toc-link.active {
  color: var(--text, #eef5ff);
  background: rgba(101,228,255,.1);
}

.doc-body {
  max-width: var(--reader-pre-measure);
  margin-inline: auto;
}

.doc-body:not(.wide),
body.reader-mode-focus .doc-body {
  max-width: var(--reader-measure);
}

body.reader-mode-wide .doc-body {
  max-width: min(1200px, calc(100vw - 2rem));
}

body.reader-mode-dense .doc-body {
  padding: 1.6rem 1.75rem;
}

body.reader-mode-comfortable .doc-body {
  font-size: 1.06rem;
}

body.reader-mode-focus .reader-toc,
body.reader-mode-focus .reader-source-card {
  display: none;
}

body.reader-mode-focus .reader-palette {
  opacity: .78;
}

.rfc-heading {
  scroll-margin-top: 6.5rem;
  display: flex;
  align-items: baseline;
  gap: .5rem;
}

.rfc-heading .heading-anchor {
  opacity: 0;
  flex: none;
  color: var(--cyan, #65e4ff) !important;
  text-decoration: none !important;
  font-size: .75em;
  transition: opacity .18s ease, transform .18s ease;
}

.rfc-heading:hover .heading-anchor {
  opacity: .85;
  transform: translateX(.1rem);
}

.doc-body h2.rfc-heading {
  margin-top: 2.4rem;
  padding: .8rem 0 .7rem;
  border-bottom: 1px solid rgba(101,228,255,.20);
}

.doc-body h3.rfc-heading {
  margin-top: 1.65rem;
  color: var(--violet, #b89cff);
}

.rfc-pretty-pre {
  position: relative;
  margin: 1.05rem 0 !important;
  padding: 1.05rem 1.1rem !important;
  border: 1px solid rgba(255,255,255,.10);
  border-radius: 1rem !important;
  background:
    linear-gradient(90deg, rgba(101,228,255,.045), transparent 18rem),
    rgba(255,255,255,.030) !important;
  color: #edf6ff !important;
  box-shadow: inset 0 1px 0 rgba(255,255,255,.05);
  tab-size: 4;
}

.rfc-pretty-pre.long-source {
  max-height: none;
}

.rfc-pretty-pre.front-matter {
  border-color: rgba(101,228,255,.18);
  background:
    radial-gradient(circle at top left, rgba(101,228,255,.09), transparent 18rem),
    rgba(255,255,255,.026) !important;
}

.rfc-pretty-pre.page-artifact {
  opacity: .72;
  border-style: dashed;
}

.normative-heavy {
  border-color: rgba(255,211,106,.20) !important;
}

.normative-keyword {
  display: inline-block;
  padding: .02rem .26rem;
  border-radius: .38rem;
  color: #ffe2a0;
  background: rgba(255,211,106,.12);
  font-weight: 900;
  letter-spacing: .02em;
}

.doc-body p,
.doc-body li {
  max-width: var(--reader-measure);
}

.doc-body blockquote {
  margin: 1.2rem 0;
  padding: .8rem 1rem;
  border-left: 4px solid var(--cyan, #65e4ff);
  border-radius: .85rem;
  background: rgba(101,228,255,.07);
  color: var(--text2, #d8e6fa);
}

.doc-body hr {
  border: 0;
  height: 1px;
  margin: 2rem 0;
  background: linear-gradient(90deg, transparent, rgba(101,228,255,.35), transparent);
}

@media (max-width: 980px) {
  .reader-palette {
    position: static;
    border-radius: 0 0 1rem 1rem;
  }

  .reader-toc {
    position: static;
    float: none;
    width: auto;
    max-height: 14rem;
    margin: 0 0 1rem;
  }

  .reader-palette-title {
    display: none;
  }
}

@media print {
  .reader-palette,
  .reader-toc,
  .heading-anchor {
    display: none !important;
  }

  .doc-body,
  .reader-source-card {
    box-shadow: none !important;
    border-color: #ddd !important;
  }
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
  const targets = links
    .map((link) => document.getElementById(link.getAttribute("href").slice(1)))
    .filter(Boolean);

  if ("IntersectionObserver" in window && targets.length) {
    const observer = new IntersectionObserver((entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (!visible) return;
      links.forEach((link) => {
        link.classList.toggle("active", link.getAttribute("href") === `#${visible.target.id}`);
      });
    }, { rootMargin: "-18% 0px -70% 0px", threshold: [0.1, 0.25, 0.5] });
    targets.forEach((target) => observer.observe(target));
  }
})();
"""
