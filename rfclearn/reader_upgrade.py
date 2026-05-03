"""Final reader cleanup for generated RFC pages.

This pass runs after the main builder and after diagram generation. It avoids
trying to fully parse RFCs, but it aggressively removes generated UI junk,
front-matter cards, note widgets, fake headings, and bogus mini-diagram cards.
"""

from __future__ import annotations

import html
import re
import textwrap
from pathlib import Path
from typing import Any

from .config import SITE_DIR

ASSET_HREF = "../assets/reader-upgrades.css"
SCRIPT_HREF = "../assets/reader-upgrades.js"
BODY_RE = re.compile(r"<body(?P<attrs>[^>]*)>", flags=re.IGNORECASE)
TITLE_RE = re.compile(r"<title>(?P<title>.*?)</title>", flags=re.IGNORECASE | re.DOTALL)
PRE_RE = re.compile(r"<pre(?P<attrs>[^>]*)>(?P<body>.*?)</pre>", flags=re.IGNORECASE | re.DOTALL)
HEADING_RE = re.compile(r"<h(?P<level>[1-6])(?P<attrs>[^>]*)>(?P<body>.*?)</h(?P=level)>", flags=re.IGNORECASE | re.DOTALL)
DIAGRAM_PANEL_RE = re.compile(
    r'<figure\b(?P<attrs>[^>]*class="[^"]*rfc-diagram-panel[^"]*"[^>]*)>.*?'
    r'<pre[^>]*>(?P<body>.*?)</pre>.*?</figure>',
    flags=re.IGNORECASE | re.DOTALL,
)
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


def _artifact_line(line: str) -> bool:
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
    kept: list[str] = []
    removed = False
    blank_run = 0
    for line in text.splitlines():
        if _artifact_line(line):
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
    # Only call something a diagram when it has multiple structural lines, not
    # merely slashes, option rows, or short labels.
    lines = [line for line in raw.splitlines() if line.strip()]
    structural_lines = sum(1 for line in lines if re.search(r"\+[-=]{3,}\+|\|.*\||[-=]{8,}|-->|<--", line))
    if len(lines) >= 3 and structural_lines >= 2:
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
        return f'<pre{_classify_pre(attrs, body, artifact_removed)}>{_highlight_normative(cleaned_body)}</pre>'
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
    return document


def _hide_inline_note_widgets(document: str) -> str:
    document = re.sub(r'<textarea\b[^>]*>.*?</textarea>', '', document, flags=re.I | re.S)
    document = re.sub(r'<button\b[^>]*>\s*Note\s*</button>', '', document, flags=re.I | re.S)
    document = re.sub(r'<[^>]+\b(?:class|id)="[^"]*(?:note|saved)[^"]*"[^>]*>\s*(?:Saved)?\s*</[^>]+>', '', document, flags=re.I | re.S)
    document = re.sub(r'(?im)^\s*Saved\s*$', '', document)
    document = re.sub(r'\s*<[^>]+>\s*Note\s*</[^>]+>', '', document, flags=re.I)
    return document


def _remove_block_containing(document: str, *needles: str) -> str:
    for tag in ("section", "article", "aside", "div"):
        pattern = re.compile(rf'<{tag}\b[^>]*>.*?</{tag}>', flags=re.I | re.S)
        def replace(match: re.Match[str]) -> str:
            text = _strip_tags(match.group(0)).lower()
            return "" if all(needle.lower() in text for needle in needles) else match.group(0)
        document = pattern.sub(replace, document)
    return document


def _remove_legacy_source_scaffolding(document: str) -> str:
    # The splash/cover scaffolding is not useful once the page itself is readable.
    document = _remove_block_containing(document, "reader mode", "cold-war fax")
    document = _remove_block_containing(document, "cover page", "rfc:")
    document = _remove_block_containing(document, "contents", "jump links live here")

    noisy_terms = (
        r'\d+\s+page\s+cards?',
        r'RFC\s+Editor\s+HTML',
        r'Page\s+breaks\s+preserved',
    )
    for term in noisy_terms:
        document = re.sub(
            r'<(?:span|li|p|div|a|button)\b[^>]*>\s*(?:<[^>]+>\s*)*'
            + term +
            r'\s*(?:</[^>]+>\s*)*</(?:span|li|p|div|a|button)>',
            '',
            document,
            flags=re.I | re.S,
        )
    return document


def _heading_label_is_junk(label: str) -> bool:
    clean = html.unescape(label).replace("#", "").strip()
    clean = re.sub(r"\s+", " ", clean)
    if not clean or len(clean) <= 2:
        return True
    if re.fullmatch(r"[\\/|+\-_=\s]+", clean):
        return True
    if re.fullmatch(r"[01]{4,}(?:\s+[01]{4,})*(?:\s*-\s*\w+)?", clean):
        return True
    if re.match(r"^\d+\s+\d+\s*-", clean):
        return True
    if re.match(r"^[A-Z0-9 ]{1,20}$", clean) and any(word in clean for word in ("CLASS", "NUMBER", "LENGTH", "DESCRIPTION")):
        return True
    if re.search(r"\b(?:occupies only|confidential|restricted|secret|efto|mmmm|prog)\b", clean, re.I):
        return True
    if len(clean) > 58 and not re.match(r"^\d+(?:\.\d+)*\s+[A-Za-z]", clean):
        return True
    junk_patterns = (
        r"^Session Complete$", r"^Prepared For$", r"^By$", r"^Editor$",
        r"^Contents$", r"^Jump Links Live Here$", r"^Table Of Contents$", r"^Preface$",
        r"^Information Processing Techniques Office$", r"^Defense Advanced Research Projects Agency$",
        r"^Information Sciences Institute$", r"^University Of Southern California$",
        r"^\d+\s+.*(?:Boulevard|Way)$", r"^(?:Arlington|Marina Del Rey),",
        r"^Application Application Program Program$", r"^Internet Module Internet Module Internet Module$",
        r"^Lni-?\d+", r"^Local Network \d+ Local Network \d+$",
        r"^Protocol Relationships$", r"^Model Of Operation$", r"^Cover Page$",
    )
    return any(re.search(pattern, clean, flags=re.I) for pattern in junk_patterns)


def _sanitize_existing_toc(document: str) -> str:
    def replace_link(match: re.Match[str]) -> str:
        body = match.group("body")
        label = _strip_tags(body)
        if _heading_label_is_junk(label):
            return ""
        cleaned_body = re.sub(r"\s*#\s*$", "", body)
        return match.group(0).replace(body, cleaned_body)
    return re.sub(
        r'<a(?P<attrs>[^>]*class="[^"]*reader-toc-link[^"]*"[^>]*)>(?P<body>.*?)</a>',
        replace_link,
        document,
        flags=re.I | re.S,
    )


def _demote_junk_headings(document: str) -> str:
    def replace_heading(match: re.Match[str]) -> str:
        body = match.group("body")
        label = _strip_tags(body)
        if not _heading_label_is_junk(label):
            return match.group(0)
        if re.search(r"[\\/|+\-_=]", label):
            return f'<pre class="rfc-readable-pre possible-diagram">{html.escape(label)}</pre>'
        return f'<p class="rfc-demoted-heading">{html.escape(label)}</p>'
    return HEADING_RE.sub(replace_heading, document)


def _looks_like_real_ascii_diagram(text: str) -> bool:
    clean = html.unescape(re.sub(r"<[^>]+>", "", text)).strip()
    lines = [line for line in clean.splitlines() if line.strip()]
    if len(lines) < 3 or len(clean) < 90:
        return False
    structural = sum(1 for line in lines if re.search(r"\+[-=]{3,}\+|\|.*\||[-=]{8,}|-->|<--", line))
    if structural < 2:
        return False
    junk_ratio = sum(ch in "\\/|+-_=<>" for ch in clean) / max(len(clean), 1)
    return junk_ratio >= .08


def _cleanup_bad_diagram_panels(document: str) -> str:
    def replace(match: re.Match[str]) -> str:
        raw = html.unescape(match.group("body"))
        normalized = textwrap.dedent(raw).strip()
        if not normalized:
            return ""
        if _looks_like_real_ascii_diagram(normalized):
            return match.group(0)
        # Tiny slash/data fragments are rendering garbage; remove them.
        stripped = re.sub(r"\s+", " ", normalized).strip()
        if len(stripped) <= 140:
            if re.fullmatch(r"[\\/|+\-_=\sA-Za-z0-9]*", stripped):
                return ""
            return f'<p class="figure-label">{html.escape(stripped)}</p>'
        return f'<pre class="rfc-readable-pre">{html.escape(normalized)}</pre>'
    return DIAGRAM_PANEL_RE.sub(replace, document)


def upgrade_document(document: str) -> str:
    document = _ensure_head_asset(document, ASSET_HREF, f'<link rel="stylesheet" href="{ASSET_HREF}">')
    document = _ensure_head_asset(document, SCRIPT_HREF, f'<script defer src="{SCRIPT_HREF}"></script>')
    document = _add_body_class(document, "reader-upgraded")
    document = _remove_legacy_source_scaffolding(document)
    document = _cleanup_bad_diagram_panels(document)
    document = _hide_inline_note_widgets(document)
    document = _demote_junk_headings(document)
    document = _sanitize_existing_toc(document)
    document = _upgrade_pre_blocks(document)
    # Run these again at the end because heading/pre transformations can reveal
    # leftover UI fragments from the original generator.
    document = _cleanup_bad_diagram_panels(document)
    document = _hide_inline_note_widgets(document)
    document = _remove_legacy_source_scaffolding(document)
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
:root { --reader-measure: 82ch; --reader-wide: 116ch; }

.reader-palette {
  position: sticky; top: 0; z-index: 50; display: flex; justify-content: space-between;
  align-items: center; gap: 1rem; width: min(1160px, calc(100% - 32px)); margin: 0 auto;
  padding: .72rem 1rem; border: 1px solid var(--line, rgba(255,255,255,.12)); border-top: 0;
  border-radius: 0 0 1.1rem 1.1rem; background: rgba(7,9,18,.88);
  backdrop-filter: blur(18px) saturate(1.25); box-shadow: 0 14px 48px rgba(0,0,0,.32);
}
.reader-palette-title { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted, #9fb0c9); font-size: .84rem; font-weight: 850; }
.reader-palette-actions { display: flex; flex-wrap: wrap; gap: .45rem; }
.reader-palette button { border: 1px solid rgba(255,255,255,.14); border-radius: 999px; padding: .38rem .7rem; color: var(--text, #eef5ff); background: rgba(255,255,255,.055); font: inherit; font-size: .76rem; font-weight: 850; cursor: pointer; }
.reader-palette button:hover, .reader-palette button.active { border-color: rgba(101,228,255,.55); background: rgba(101,228,255,.16); color: var(--cyan, #65e4ff); }

body.reader-upgraded .doc-layout { width: min(1240px, calc(100% - 28px)); }
body.reader-upgraded .doc-body { max-width: var(--reader-wide) !important; margin-inline: auto; padding: clamp(1.25rem, 3vw, 3rem) !important; overflow: visible; }
body.reader-mode-focus .doc-body, body.reader-mode-comfortable .doc-body { max-width: var(--reader-measure) !important; }
body.reader-mode-wide .doc-body { max-width: min(1220px, calc(100vw - 2rem)) !important; }
body.reader-mode-dense .doc-body { padding: 1.3rem 1.5rem !important; }
body.reader-mode-focus .reader-palette { opacity: .78; }

.rfc-readable-pre {
  max-width: var(--reader-measure); margin: 1.2rem auto !important; padding: 0 !important; border: 0 !important;
  border-radius: 0 !important; background: transparent !important; box-shadow: none !important; color: #dce8f8 !important;
  font: 1.02rem/1.78 "IBM Plex Mono", "SFMono-Regular", Consolas, monospace !important;
  white-space: pre-wrap !important; overflow-wrap: anywhere; word-break: normal; tab-size: 4;
}
body.reader-mode-dense .rfc-readable-pre { font-size: .92rem !important; line-height: 1.55 !important; }
body.reader-mode-wide .rfc-readable-pre { max-width: var(--reader-wide); }
.rfc-readable-pre.possible-diagram { padding: .9rem 1rem !important; border: 1px solid rgba(255,255,255,.10) !important; border-radius: 1rem !important; background: rgba(255,255,255,.028) !important; overflow-x: auto; overflow-wrap: normal; }

.rfc-demoted-heading, .figure-label { max-width: var(--reader-measure); margin: .8rem auto; color: #dce8f8; font: 1.02rem/1.7 "IBM Plex Mono", "SFMono-Regular", Consolas, monospace; }
.rfc-muted-artifact { display: none !important; }
.normative-keyword { display: inline-block; padding: .02rem .28rem; border-radius: .38rem; color: #ffe2a0; background: rgba(255,211,106,.13); font-weight: 900; letter-spacing: .02em; }

textarea, button.note-btn, .note-status, .section-note, .inline-note, [class*="note"], [id*="note"], .legacy-source-scaffold, .source-scaffold, .source-meta, .page-card-meta { display: none !important; }

@media (max-width: 780px) { .reader-palette { position: static; border-radius: 0 0 1rem 1rem; } .reader-palette-title { display: none; } .rfc-readable-pre { font-size: .92rem !important; } }
@media print { .reader-palette { display: none !important; } .doc-body { box-shadow: none !important; border-color: #ddd !important; } }
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

  function removeNearestCard(node) {
    const card = node.closest("section, article, aside, .card, .panel, .source-card, .source-panel, div");
    if (card) card.remove();
  }

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-reader-mode]");
    if (!button) return;
    setMode(button.dataset.readerMode);
  });

  document.querySelectorAll("button").forEach((button) => {
    if (button.textContent.trim().toLowerCase() === "note") button.remove();
  });
  document.querySelectorAll("textarea").forEach((textarea) => textarea.remove());
  document.querySelectorAll("body *").forEach((node) => {
    const text = node.textContent.trim();
    if (node.childNodes.length === 1 && text === "Saved") node.remove();
    if (/reader mode/i.test(text) && /cold-war fax/i.test(text)) removeNearestCard(node);
    if (/cover page/i.test(text) && /RFC:\s*\d+/i.test(text)) removeNearestCard(node);
    if (/^\d+\s+page\s+cards?$/i.test(text) || /^RFC\s+Editor\s+HTML$/i.test(text) || /^Page\s+breaks\s+preserved$/i.test(text)) node.remove();
    if (/JUMP\s+LINKS\s+LIVE\s+HERE/i.test(text) && /CONTENTS/i.test(text)) removeNearestCard(node);
  });
  document.querySelectorAll(".rfc-diagram-panel").forEach((figure) => {
    const text = figure.textContent.replace(/Original ASCII/i, "").trim();
    if (text.length < 140 && !/[+|][-=]{3,}|-->|<--/.test(text)) figure.remove();
  });

  setMode(localStorage.getItem(storageKey) || "comfortable");
})();
"""
