"""Stable reader-experience upgrades for generated RFC pages.

This module deliberately avoids parsing RFC plaintext into new document
structure. Earlier semantic conversion was too aggressive for historical RFC
formatting. The stable approach is: preserve source structure, hide obvious page
artifacts, improve typography, and keep the layout simple.
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

from .config import SITE_DIR

ASSET_HREF = "../assets/reader-upgrades.css"
SCRIPT_HREF = "../assets/reader-upgrades.js"
BODY_RE = re.compile(r"<body(?P<attrs>[^>]*)>", flags=re.IGNORECASE)
TITLE_RE = re.compile(r"<title>(?P<title>.*?)</title>", flags=re.IGNORECASE | re.DOTALL)
PRE_RE = re.compile(r"<pre(?P<attrs>[^>]*)>(?P<body>.*?)</pre>", flags=re.IGNORECASE | re.DOTALL)
NORMATIVE_RE = re.compile(r"\b(MUST NOT|SHOULD NOT|MUST|SHOULD|MAY|REQUIRED|RECOMMENDED|OPTIONAL)\b")


def _strip_tags(value: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", " ", value)).strip()


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


def _is_artifact_line(line: str) -> bool:
    clean = html.unescape(re.sub(r"<[^>]+>", "", line)).strip()
    if not clean:
        return False
    if "[Page " in clean or re.fullmatch(r"\[?[Pp]age\s+\d+\]?", clean):
        return True
    if re.match(r"^(Network Working Group|Request for Comments|Category:|Updates:|Obsoletes:)\b", clean, re.I):
        return True
    if re.fullmatch(r"(DARPA\s+INTERNET\s+PROGRAM|PROTOCOL\s+SPECIFICATION|INTERNET\s+PROTOCOL)", clean, re.I):
        return True
    if re.fullmatch(r"[-_\s]{8,}", clean):
        return True
    return False


def _clean_pre_body(body: str) -> tuple[str, bool]:
    text = html.unescape(re.sub(r"<[^>]+>", "", body)).replace("\r", "")
    lines = text.splitlines()
    kept: list[str] = []
    removed = False
    blank_run = 0

    for line in lines:
        if _is_artifact_line(line):
            removed = True
            continue
        if not line.strip():
            blank_run += 1
            if blank_run <= 2:
                kept.append("")
            else:
                removed = True
            continue
        blank_run = 0
        kept.append(line.rstrip())

    cleaned = "\n".join(kept).strip("\n")
    return html.escape(cleaned), removed


def _classify_pre(attrs: str, body: str, artifact_removed: bool) -> str:
    raw = html.unescape(re.sub(r"<[^>]+>", "", body))
    classes = ["rfc-readable-pre"]
    if artifact_removed:
        classes.append("artifacts-cleaned")
    if NORMATIVE_RE.search(raw):
        classes.append("normative-heavy")
    if any(ch in raw for ch in "+-|_:/\\<>[]{}=*~^`"):
        classes.append("possible-diagram")
    class_text = " ".join(classes)
    if 'class="' in attrs:
        return re.sub(r'class="([^"]*)"', lambda m: f'class="{m.group(1)} {class_text}"', attrs, count=1)
    return attrs + f' class="{class_text}"'


def _highlight_normative(body: str) -> str:
    return NORMATIVE_RE.sub(r'<span class="normative-keyword">\1</span>', body)


def _upgrade_pre_blocks(document: str) -> str:
    def replace(match: re.Match[str]) -> str:
        attrs = match.group("attrs") or ""
        body = match.group("body")
        whole = match.group(0)
        if "rfc-diagram-source" in whole or "data-rfclearn-diagram" in whole:
            return whole
        cleaned_body, artifact_removed = _clean_pre_body(body)
        if not cleaned_body.strip():
            return ""
        cleaned_body = _highlight_normative(cleaned_body)
        return f'<pre{_classify_pre(attrs, body, artifact_removed)}>{cleaned_body}</pre>'

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


def _hide_inline_note_widgets(document: str) -> str:
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
  --reader-measure: 82ch;
  --reader-wide: 116ch;
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
  padding: .72rem 1rem;
  border: 1px solid var(--line, rgba(255,255,255,.12));
  border-top: 0;
  border-radius: 0 0 1.1rem 1.1rem;
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
  font-size: .84rem;
  font-weight: 850;
}

.reader-palette-actions { display: flex; flex-wrap: wrap; gap: .45rem; }
.reader-palette button {
  border: 1px solid rgba(255,255,255,.14);
  border-radius: 999px;
  padding: .38rem .7rem;
  color: var(--text, #eef5ff);
  background: rgba(255,255,255,.055);
  font: inherit;
  font-size: .76rem;
  font-weight: 850;
  cursor: pointer;
}
.reader-palette button:hover,
.reader-palette button.active {
  border-color: rgba(101,228,255,.55);
  background: rgba(101,228,255,.16);
  color: var(--cyan, #65e4ff);
}

body.reader-upgraded .doc-layout {
  width: min(1240px, calc(100% - 28px));
}

body.reader-upgraded .doc-body {
  max-width: var(--reader-wide) !important;
  margin-inline: auto;
  padding: clamp(1.25rem, 3vw, 3rem) !important;
  overflow: visible;
}

body.reader-mode-focus .doc-body,
body.reader-mode-comfortable .doc-body {
  max-width: var(--reader-measure) !important;
}

body.reader-mode-wide .doc-body {
  max-width: min(1220px, calc(100vw - 2rem)) !important;
}

body.reader-mode-dense .doc-body {
  padding: 1.3rem 1.5rem !important;
}

body.reader-mode-focus .reader-palette {
  opacity: .78;
}

.rfc-readable-pre {
  max-width: var(--reader-measure);
  margin: 1.2rem auto !important;
  padding: 0 !important;
  border: 0 !important;
  border-radius: 0 !important;
  background: transparent !important;
  box-shadow: none !important;
  color: #dce8f8 !important;
  font: 1.02rem/1.78 "IBM Plex Mono", "SFMono-Regular", Consolas, monospace !important;
  white-space: pre-wrap !important;
  overflow-wrap: anywhere;
  word-break: normal;
  tab-size: 4;
}

body.reader-mode-dense .rfc-readable-pre {
  font-size: .92rem !important;
  line-height: 1.55 !important;
}

body.reader-mode-wide .rfc-readable-pre {
  max-width: var(--reader-wide);
}

.rfc-readable-pre.possible-diagram {
  padding: .9rem 1rem !important;
  border: 1px solid rgba(255,255,255,.10) !important;
  border-radius: 1rem !important;
  background: rgba(255,255,255,.028) !important;
  overflow-x: auto;
  overflow-wrap: normal;
}

.normative-keyword {
  display: inline-block;
  padding: .02rem .28rem;
  border-radius: .38rem;
  color: #ffe2a0;
  background: rgba(255,211,106,.13);
  font-weight: 900;
  letter-spacing: .02em;
}

/* Kill old inline notes that interrupt RFC text. */
textarea[placeholder="Add your notes for this section..."] { display: none !important; }
button.note-btn,
.note-status,
.section-note,
.inline-note { display: none !important; }

@media (max-width: 780px) {
  .reader-palette { position: static; border-radius: 0 0 1rem 1rem; }
  .reader-palette-title { display: none; }
  .rfc-readable-pre { font-size: .92rem !important; }
}

@media print {
  .reader-palette { display: none !important; }
  .doc-body { box-shadow: none !important; border-color: #ddd !important; }
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
})();
"""
