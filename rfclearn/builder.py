"""Main builder functions for RFC Learn."""

import hashlib
import html
import json
import re

import shutil
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable

try:
    from ebooklib import epub
except ImportError as exc:
    raise SystemExit(
        "ebooklib is required. Install dependencies with: python3 -m pip install -r requirements.txt"
    ) from exc

from .models import RFCMeta, RFCBuild
from .config import (
    ROOT, DATA_DIR, SITE_DIR, EPUB_DIR, RFC_BASE,
    RFCS, TAG_DESCRIPTIONS, STUDY_TRACKS, SCIENCE_NOTES,
    HEADER_REFERENCES, THREAT_INDICATORS, DETECTION_QUESTIONS,
    KNOWN_RFC_TAG_GROUPS, KNOWN_RFC_TAGS, RELATION_RE, RFC_NUM_RE,
)

try:
    with open(ROOT / "diagram_cache.json", "r") as f:
        DIAGRAM_CACHE = json.load(f)
except FileNotFoundError:
    DIAGRAM_CACHE = {}

from .templates import SITE_CSS, INDEX_JS, DOC_JS

from . import diagram_renderer

def slug(meta: RFCMeta) -> str:
    return f"rfc{meta.num}.html"


def ensure_dirs() -> None:
    for directory in (DATA_DIR / "txt", DATA_DIR / "html", SITE_DIR / "rfc", SITE_DIR / "assets", EPUB_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def fetch_url(url: str, dest: Path) -> tuple[bool, str | None]:
    if dest.exists() and dest.stat().st_size > 0:
        return True, None
    req = urllib.request.Request(url, headers={"User-Agent": "rfc-threat-hunting-builder/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=35) as response:
            data = response.read()
        dest.write_bytes(data)
        time.sleep(0.15)
        return True, None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, str(exc)


def fetch_one(meta: RFCMeta, depth: int = 0) -> RFCBuild:
    ensure_dirs()
    item = RFCBuild(meta=meta, depth=depth)
    txt = DATA_DIR / "txt" / f"rfc{meta.num}.txt"
    html_file = DATA_DIR / "html" / f"rfc{meta.num}.html"
    item.text_ok, item.text_error = fetch_url(RFC_BASE.format(num=meta.num, ext="txt"), txt)
    item.html_ok, item.html_error = fetch_url(RFC_BASE.format(num=meta.num, ext="html"), html_file)
    item.text_path = txt if item.text_ok else None
    item.html_path = html_file if item.html_ok else None
    return item


def parse_related_rfcs(text: str) -> set[int]:
    related: set[int] = set()
    header = text[:45000]

    def nums_from_segment(segment: str) -> set[int]:
        href_nums = re.findall(r"href=[\"'][^\"']*rfc(\d{3,5})", segment, flags=re.I)
        if href_nums:
            return {int(num) for num in href_nums}
        return {int(num) for num in RFC_NUM_RE.findall(segment)}

    for match in re.finditer(r"\b(?:Updated by|Obsoletes|Obsoleted by):.*?</span>", header, flags=re.I | re.S):
        related.update(nums_from_segment(match.group(0)))
    for match in RELATION_RE.finditer(header):
        related.update(nums_from_segment(match.group("body")))
    return related


TITLE_STOP_LINE_RE = re.compile(
    r"(?i)^(?:status(?:\s+of\s+this\s+memo)?|abstract|copyright\s+notice|table\s+of\s+contents|contents|introduction|overview|acknowledg(?:e)?ment|1\s*[-.]\s+[A-Za-z])$"
)
TITLE_METADATA_RE = re.compile(
    r"(?i)^(?:network working group|internet engineering task force|internet architecture board|request for comments|rfc\s*:?\s*\d+|category:|updates?:|updated by:|obsoletes?:|obsoleted by:|std:|bcp:|fyi:|issn:)"
)
TITLE_DATE_RE = re.compile(
    r"(?i)^(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\s+\d{4}$"
)
TITLE_AUTHOR_RE = re.compile(
    r"^(?:[A-Z]\.\s*){1,3}[A-Z][A-Za-z'`.-]+(?:\s+(?:[A-Z][A-Za-z'`.-]+|[23](?:rd)?|Jr\.?|Sr\.?)){0,4}$"
)
TITLE_PROTOCOL_HINTS = (
    "protocol", "internet", "domain", "dns", "tcp", "udp", "http", "mail", "smtp", "dhcp", "bgp",
    "ospf", "uri", "security", "authentication", "names", "subnet", "ip", "ipv6", "ipv4", "zone",
    "cache", "routing", "header", "message", "packet", "congestion", "label", "semantics", "transport",
)


def clean_title_line(line: str) -> str:
    return re.sub(r"\s+", " ", line.replace("\ufeff", "")).strip()


def parse_html_title(raw: str, num: int) -> str | None:
    match = re.search(rf"<title>\s*RFC\s+{num}\s*:?\s*(.*?)\s*</title>", raw, flags=re.I | re.S)
    if not match:
        match = re.search(r"<title>\s*RFC\s+\d+\s*:?\s*(.*?)\s*</title>", raw, flags=re.I | re.S)
    if not match:
        return None
    title = html.unescape(re.sub(r"\s+", " ", match.group(1))).strip(" -:")
    return title or None


def cached_html_path(build: RFCBuild) -> Path | None:
    candidates = [build.html_path, DATA_DIR / "html" / f"rfc{build.meta.num}.html"]
    for path in candidates:
        if path and path.exists():
            return path
    return None


def looks_like_title_line(clean: str, raw: str) -> bool:
    if not clean or len(clean) < 6 or len(clean) > 120:
        return False
    if TITLE_METADATA_RE.match(clean) or TITLE_STOP_LINE_RE.match(clean) or TITLE_DATE_RE.match(clean):
        return False
    if "[page" in clean.lower():
        return False
    if clean.startswith(("+", "|")) or set(clean) <= {"-", "*", "_", "=", "+", "|", ".", " "}:
        return False
    if re.fullmatch(r"[IVXLCDM]+", clean):
        return False
    if clean.endswith("."):
        return False
    if TITLE_AUTHOR_RE.fullmatch(clean):
        return False
    if re.search(r"\b(?:telephone|phone|facsimile|fax)\b", clean, flags=re.I):
        return False
    words = re.findall(r"[A-Za-z0-9][A-Za-z0-9'()/.-]*", clean)
    if len(words) < 2 or len(words) > 18:
        return False
    alpha_chars = [ch for ch in clean if ch.isalpha()]
    if not alpha_chars:
        return False
    uppercase_ratio = sum(1 for ch in alpha_chars if ch.isupper()) / len(alpha_chars)
    titleish_words = sum(1 for word in words if word[:1].isupper() or word.isupper())
    hint_hits = sum(1 for hint in TITLE_PROTOCOL_HINTS if hint in clean.lower())
    lead_spaces = len(raw) - len(raw.lstrip(" "))
    if uppercase_ratio >= 0.45 or titleish_words / len(words) >= 0.7:
        return True
    return bool(hint_hits and lead_spaces >= 4)


def looks_like_title_continuation(clean: str, raw: str) -> bool:
    if not clean or len(clean) < 3 or len(clean) > 90:
        return False
    if TITLE_METADATA_RE.match(clean) or TITLE_STOP_LINE_RE.match(clean) or TITLE_DATE_RE.match(clean):
        return False
    if TITLE_AUTHOR_RE.fullmatch(clean) or clean.endswith("."):
        return False
    if "[page" in clean.lower():
        return False
    words = re.findall(r"[A-Za-z0-9][A-Za-z0-9'()/.-]*", clean)
    if not words or len(words) > 10:
        return False
    lead_spaces = len(raw) - len(raw.lstrip(" "))
    if clean[:1].islower():
        return True
    return lead_spaces >= 8 and words[0].lower() in {"and", "or", "for", "of", "to", "the", "with", "using", "in"}


def score_title_block(lines: list[tuple[str, str]], start_index: int) -> int:
    title = " ".join(clean for clean, _raw in lines)
    hint_hits = sum(1 for hint in TITLE_PROTOCOL_HINTS if hint in title.lower())
    lead_space_bonus = sum(1 for _clean, raw in lines if len(raw) - len(raw.lstrip(" ")) >= 8)
    uppercase_bonus = 0
    for clean, _raw in lines:
        alpha_chars = [ch for ch in clean if ch.isalpha()]
        if alpha_chars and sum(1 for ch in alpha_chars if ch.isupper()) / len(alpha_chars) >= 0.55:
            uppercase_bonus += 1
    score = len(lines) * 4 + hint_hits * 3 + lead_space_bonus + uppercase_bonus
    score += max(0, 22 - start_index)
    if re.search(r"\b(?:inc|corp|labs|university|institute|motorola|nominum|stanford)\b", title, flags=re.I):
        score -= 10
    return score


def extract_title_from_text(text: str, num: int) -> str | None:
    lines = text.replace("\r", "").replace("\ufeff", "").splitlines()
    candidates: list[tuple[int, int, list[tuple[str, str]]]] = []
    current: list[tuple[str, str]] = []
    current_start = 0

    for index, raw_line in enumerate(lines[:120]):
        clean = clean_title_line(raw_line)
        if TITLE_STOP_LINE_RE.match(clean):
            if current:
                candidates.append((score_title_block(current, current_start), current_start, current))
            current = []
            break
        if not clean:
            if current:
                candidates.append((score_title_block(current, current_start), current_start, current))
                current = []
            continue
        direct_match = re.match(rf"^RFC\s+{num}\s*[-:]\s*(.+)$", clean, flags=re.I)
        if direct_match:
            direct_title = clean_title_line(direct_match.group(1)).strip(" -:")
            if direct_title and not TITLE_DATE_RE.match(direct_title):
                return direct_title
        if looks_like_title_line(clean, raw_line) or (current and looks_like_title_continuation(clean, raw_line)):
            if not current:
                current_start = index
            current.append((clean, raw_line))
            if len(current) == 3:
                candidates.append((score_title_block(current, current_start), current_start, current))
                current = []
        elif current:
            candidates.append((score_title_block(current, current_start), current_start, current))
            current = []

    if current:
        candidates.append((score_title_block(current, current_start), current_start, current))

    if candidates:
        best_block = max(candidates, key=lambda item: (item[0], -item[1]))[2]
        title = " ".join(clean for clean, _raw in best_block).strip(" -:")
        if title:
            return title

    for raw_line in lines[:120]:
        clean = clean_title_line(raw_line)
        if clean and not TITLE_METADATA_RE.match(clean) and not TITLE_DATE_RE.match(clean):
            if len(clean) > 8:
                return clean
    return None


def extract_title(build: RFCBuild) -> str:
    html_path = cached_html_path(build)
    if html_path:
        title = parse_html_title(read_text(html_path), build.meta.num)
        if title:
            return title
    text = read_text(build.text_path)
    title = extract_title_from_text(text, build.meta.num)
    if title:
        return title
    return f"RFC {build.meta.num}"


def infer_tags(title: str, num: int | None = None) -> tuple[str, ...]:
    if num in KNOWN_RFC_TAGS:
        return KNOWN_RFC_TAGS[num]
    lower = title.lower()
    tags: set[str] = {"update-chain"}
    if any(word in lower for word in ("tcp", "udp", "transport", "stream", "flow control", "encapsulat", "payload")):
        tags.add("transport")
    if any(word in lower for word in ("http", "smtp", "dns", "dhcp", "mail", "domain", "uri", "service")):
        tags.add("application")
    if any(word in lower for word in ("ip", "ipv6", "icmp", "ospf", "bgp", "route", "routing", "address", "arp", "neighbor")):
        tags.add("routing")
    if any(word in lower for word in ("flow", "ipfix", "netflow", "monitor", "export", "telemetry", "logging")):
        tags.add("monitoring")
    if any(word in lower for word in ("security", "secure", "ipsec", "esp", "auth", "encryption", "dnssec", "threat", "attack", "privacy")):
        tags.add("security")
    return tuple(tag for tag in TAG_DESCRIPTIONS if tag in tags)


def extract_summary_source(build: RFCBuild) -> str:
    if build.text_ok and build.text_path:
        return read_text(build.text_path)
    if build.html_ok and build.html_path:
        return html.unescape(re.sub(r"<[^>]+>", " ", extract_body(read_text(build.html_path))))
    return ""


def clean_summary_text(text: str) -> str:
    text = text.replace("\ufeff", "").replace("\r", "").replace("\f", "\n")
    text = re.sub(r"\[[^\]]+\]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def split_sentences(text: str) -> list[str]:
    if not text:
        return []
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9\"'])", text)
    return [part.strip() for part in parts if part.strip()]


def extract_abstract_or_intro(build: RFCBuild) -> str:
    source = extract_summary_source(build).replace("\ufeff", "").replace("\r", "").replace("\f", "\n")
    if not source:
        return ""

    abstract_match = re.search(
        r"(?ims)^\s*Abstract\s*$\s*(?P<body>.*?)(?=^\s*(?:Status of This Memo|Copyright Notice|Table of Contents|1\.\s+Introduction)\b)",
        source,
    )
    if abstract_match:
        body = abstract_match.group("body")
        paragraphs = [clean_summary_text(chunk) for chunk in re.split(r"\n\s*\n", body) if clean_summary_text(chunk)]
        summary = " ".join(paragraphs[:2])
        return " ".join(split_sentences(summary)[:3])

    intro_heading = re.compile(r"(?im)^\s*1\.\s+Introduction\s*$")
    next_heading = re.compile(r"(?im)^\s*2\.\s+[A-Za-z]")
    for match in intro_heading.finditer(source):
        start = match.end()
        window = source[start:start + 900]
        if window.count(".") > 25 and "..." in window[:300]:
            continue
        stop_match = next_heading.search(source, start)
        body = source[start:stop_match.start()] if stop_match else source[start:start + 1400]
        paragraphs = [clean_summary_text(chunk) for chunk in re.split(r"\n\s*\n", body) if clean_summary_text(chunk)]
        if not paragraphs:
            continue
        summary = " ".join(paragraphs[:2])
        return " ".join(split_sentences(summary)[:3])

    cleaned = clean_summary_text(source[:1200])
    return " ".join(split_sentences(cleaned)[:2])


def infer_protocol_label(title: str, summary: str, tags: tuple[str, ...]) -> str:
    combined = f"{title} {summary}".lower()
    checks = (
        ("DNS", ("dns", "domain name system", "dnssec", "rrset", "resolver", "zone transfer", "qtype=any", "nxdomain")),
        ("BGP", ("bgp", "as_path", "as 0", "graceful restart", "route propagation")),
        ("OSPF", ("ospf", "lsa", "router alert", "adjacency")),
        ("SMTP", ("smtp", "mail transfer", "ehlo", "mail relay")),
        ("HTTP", ("http", "http/1.1", "http/2", "content-disposition", "status code")),
        ("DHCP", ("dhcp", "lease", "relay agent", "bootp")),
        ("IPsec", ("security architecture for the internet protocol", "ipsec", "security association")),
        ("ESP", ("encapsulating security payload", "esp ")),
        ("IPv6", ("ipv6", "icmpv6", "extension header", "atomic fragments", "flow label", "teredo", "6to4")),
        ("IPv4", ("ipv4", "type of service", "differentiated services", "ecn to ip")),
        ("TCP", ("tcp", "sequence number", "retransmission timer", "persist condition", "urgent")),
        ("UDP", ("udp", "datagram", "udp-lite", "checksum", "transport options")),
        ("IPFIX", ("ipfix", "flow information export")),
        ("NetFlow", ("netflow",)),
        ("MPLS", ("mpls", "label switched path", "lsp ping", "pseudowire")),
        ("URI", ("uri", "well-known uniform resource identifiers", "uri schemes")),
    )
    for label, needles in checks:
        if any(needle in combined for needle in needles):
            return label
    if "application" in tags:
        return "application protocol"
    if "transport" in tags:
        return "transport protocol"
    if "routing" in tags:
        return "routing protocol"
    if "security" in tags:
        return "security protocol"
    return "protocol"


def normalize_title_focus(title: str) -> str:
    focus = " ".join(title.split()).strip().rstrip(".")
    replacements = (
        ("Providing ", ""),
        ("Revised ", ""),
        ("Additional ", ""),
        ("The Addition of ", ""),
        ("On the Implementation of ", "implementation of "),
        ("Recommendation for Not Using ", "avoidance of "),
        ("Defending Against ", "defense against "),
        ("Improving ", "improved "),
        ("Upgrading to ", "upgrades to "),
        ("Handling of ", ""),
        ("Handling ", ""),
        ("Serving ", ""),
        ("Using ", "use of "),
        ("Detecting ", "detection of "),
        ("Representing ", "representation of "),
        ("Deprecating the Use of ", "deprecation of "),
        ("Deprecating ", "deprecation of "),
        ("Notification Message Support for ", "notification support for "),
        ("Update to ", ""),
        ("Updates to ", ""),
    )
    for old, new in replacements:
        if focus.startswith(old):
            focus = new + focus[len(old):]
            break
    return focus


def update_subject_phrase(title: str, summary: str, protocol: str) -> str:
    combined = f"{title} {summary}".lower()
    rules = (
        (r"simple mail transfer protocol", "SMTP command, relay, and reply behavior"),
        (r"domain names? - concepts and facilities|domain names?: concepts and facilities", "foundational DNS naming and delegation behavior"),
        (r"domain names? - implementation and specification|domain names?: implementation specification", "core DNS message and record behavior"),
        (r"dynamic host configuration protocol", "DHCP lease, relay, and option behavior"),
        (r"ospf version 2", "OSPFv2 adjacency and link-state behavior"),
        (r"security architecture for the internet protocol", "IPsec security architecture"),
        (r"ip encapsulating security payload|encapsulating security payload", "ESP packet protection behavior"),
        (r"internet protocol, version 6|ipv6 specification", "foundational IPv6 packet behavior"),
        (r"a border gateway protocol 4|bgp-4", "BGP-4 route advertisement behavior"),
        (r"qtype=any|any queries|any query", "DNS responder behavior for QTYPE=ANY queries"),
        (r"nxdomain", "DNS NXDOMAIN handling for entire denied subtrees"),
        (r"negative caching", "DNS negative caching behavior"),
        (r"zone transfer over tls", "DNS zone transfer over TLS"),
        (r"zone transfer|axfr", "DNS zone transfer behavior"),
        (r"dynamic update", "DNS dynamic update behavior"),
        (r"dns notify|dns notify|zone changes", "DNS zone-change notifications"),
        (r"delegation signer|\bds\b", "DNSSEC delegation-signer handling"),
        (r"authenticated data \(ad\) bit|authenticated data bit| ad bit", "DNSSEC authenticated-data signaling"),
        (r"aggressive use.*dnssec|dnssec.*aggressive use", "aggressive use of validated DNSSEC cache data"),
        (r"serving stale", "DNS stale-answer serving"),
        (r"dns terminology", "modern DNS terminology"),
        (r"transport over tcp", "DNS transport over TCP"),
        (r"tsig|transaction authentication", "TSIG-based DNS transaction authentication"),
        (r"revised error handling|error handling.*bgp", "BGP UPDATE error handling"),
        (r"graceful restart", "BGP graceful restart behavior"),
        (r"four-octet.*as|four octet.*as", "BGP four-octet ASN handling"),
        (r"extended message", "larger BGP message handling"),
        (r"optional parameters length", "BGP OPEN optional-parameter encoding"),
        (r"\bas 0\b", "BGP handling of AS 0"),
        (r"send hold timer", "BGP send-hold-timer behavior"),
        (r"hmac-sha|cryptographic authentication", "OSPFv2 cryptographic authentication"),
        (r"multi-instance", "OSPF multi-instance behavior"),
        (r"\bbfd\b", "OSPF fast-failure signaling with BFD"),
        (r"manual key management", "OSPFv2 manual-key security behavior"),
        (r"flow label", "IPv6 flow-label behavior"),
        (r"extension headers", "IPv6 extension-header processing"),
        (r"atomic fragments|overlapping ipv6 fragments|fragment", "IPv6 fragment handling"),
        (r"router alert", "IPv6 Router Alert behavior"),
        (r"\becn\b|explicit congestion notification", "ECN handling across IP and tunnels"),
        (r"retransmission timer", "TCP retransmission-timer calculation"),
        (r"urgent", "TCP urgent-pointer behavior"),
        (r"blind in-window", "TCP resistance to blind in-window attacks"),
        (r"sequence number attacks", "TCP sequence-number hardening"),
        (r"persist condition", "TCP persist behavior"),
        (r"maximum segment size|\bmss\b", "TCP MSS handling"),
        (r"transmission control protocol \(tcp\)|obsoletes rfc 793", "the consolidated TCP base specification"),
        (r"transport options", "UDP transport options"),
        (r"checksum", "UDP checksum handling for tunnels"),
        (r"algorithm.*esp|encapsulating security payload.*algorithm", "ESP algorithm requirements"),
        (r"http over tls", "HTTP over TLS"),
        (r"http/2.*tls 1\.3|tls 1\.3.*http/2", "HTTP/2 operation over TLS 1.3"),
        (r"authentication", "HTTP authentication behavior"),
        (r"status code 308|additional http status codes", "HTTP status-code handling"),
        (r"content-disposition", "HTTP content-disposition parsing"),
        (r"smtp.*extension|service extensions", "SMTP command and extension behavior"),
        (r"internationalized email", "SMTP support for internationalized addresses"),
        (r"flow information export|netflow|ipfix", "flow-export telemetry behavior"),
        (r"uri schemes|well-known uniform resource identifiers", "URI scheme and well-known-URI handling"),
    )
    for pattern, phrase in rules:
        if re.search(pattern, combined):
            return phrase

    focus = normalize_title_focus(title)
    if not focus:
        return f"{protocol} behavior"
    protocol_aliases = {
        "SMTP": ("smtp", "mail transfer"),
        "HTTP": ("http", "hypertext"),
        "TCP": ("tcp", "transmission control protocol"),
        "UDP": ("udp", "user datagram"),
        "DNS": ("dns", "domain name"),
        "BGP": ("bgp", "border gateway protocol"),
        "OSPF": ("ospf",),
        "DHCP": ("dhcp", "host configuration"),
        "IPv6": ("ipv6", "internet protocol, version 6"),
        "IPv4": ("ipv4", "internet protocol"),
        "ESP": ("esp", "encapsulating security payload"),
        "IPsec": ("ipsec", "security architecture for the internet protocol"),
        "IPFIX": ("ipfix", "flow information export"),
        "NetFlow": ("netflow",),
        "URI": ("uri", "uniform resource identifier"),
    }
    aliases = protocol_aliases.get(protocol, (protocol.lower(),))
    if protocol != "protocol" and not any(alias in focus.lower() for alias in aliases):
        if len(focus.split()) <= 6 and re.search(r"\b(protocol|version|specification)\b", focus, flags=re.I):
            return f"foundational {protocol} behavior"
        if re.match(r"^(deprecation|avoidance|implementation|representation|use)\b", focus, flags=re.I):
            return f"{protocol} {focus}"
        return f"{focus} in {protocol}"
    return focus


def update_lead_verb(title: str, summary: str, has_abstract: bool) -> str:
    combined = f"{title} {summary}".lower()
    title_lower = title.lower()
    if any(word in combined for word in ("deprecat", "obsolet", "not using")):
        return "Deprecates"
    if "error handling" in combined or "revised " in title_lower:
        return "Revises"
    if any(word in combined for word in ("clarif", "redefinition", "states clearly", "terminology")):
        return "Clarifies"
    if any(word in combined for word in ("guidance", "guidelines", "requirements", "procedures", "considerations")):
        return "Guides"
    if any(word in combined for word in ("dnssec", "tsig", "authentication", "integrity", "tls", "hmac", "sha-1")):
        return "Strengthens"
    if any(word in combined for word in ("support for", "additional", "option", "options", "extensions", "extended")):
        return "Extends"
    if any(word in combined for word in ("specifies", "defines", "protocol", "resource record", "format", "encoding")):
        return "Defines"
    if not has_abstract:
        return "Documents"
    return "Updates"


def update_why_care(protocol: str, title: str, summary: str, tags: tuple[str, ...]) -> str:
    combined = f"{title} {summary}".lower()
    if "qtype=any" in combined or "any query" in combined:
        return "Useful for interpreting amplification-resistant DNS behavior and why modern authoritative servers may return lean or policy-driven ANY answers."
    if "nxdomain" in combined:
        return "Relevant when negative answers shape cache behavior, subtree enumeration, or why an entire branch of names disappears from resolution."
    if protocol == "BGP" and "error handling" in combined:
        return "Matters because malformed attributes no longer have to look like full-session failure, which changes how route churn and peer resets should be read."
    if protocol == "UDP" and "options" in combined:
        return "Hunters should know which post-payload bytes are legitimate extensions before treating them as malformed data, covert signaling, or middlebox breakage."
    if protocol == "DNS":
        return "Useful for interpreting resolver behavior, amplification controls, signed data, and suspicious DNS responses during hunts."
    if protocol == "BGP":
        return "Relevant when route leaks, malformed attributes, failover behavior, or policy changes affect what normal routing churn should look like."
    if protocol == "OSPF":
        return "Relevant when adjacency rules, authentication, or LSA handling change what route manipulation and control-plane noise should look like."
    if protocol in {"IPv4", "IPv6", "TCP", "UDP"}:
        return "Useful for recognizing modern baseline wire behavior, parser edge cases, and traffic patterns that may look malicious if you expect older semantics."
    if protocol in {"HTTP", "SMTP", "DHCP", "URI"}:
        return "Useful for parsing application traffic correctly and spotting behavior that modern clients, servers, or intermediaries should no longer treat as normal."
    if protocol in {"IPsec", "ESP"} or "security" in tags:
        return "Relevant when validating protected sessions, negotiated algorithms, and why traffic is accepted, rejected, or downgraded."
    if protocol in {"IPFIX", "NetFlow", "MPLS"} or "monitoring" in tags:
        return "Useful for telemetry normalization, exporter validation, and avoiding false positives when formats or control messages change."
    if any(word in combined for word in ("deprecat", "obsolet", "not using")):
        return "Useful for spotting legacy behavior that still appears on the wire even though current guidance expects it to disappear."
    return "Useful for understanding the newer baseline so defenders do not mistake standards drift for malicious behavior."


def generate_update_chain_relevance(title: str, build: RFCBuild, tags: tuple[str, ...]) -> str:
    summary = extract_abstract_or_intro(build)
    protocol = infer_protocol_label(title, summary, tags)
    subject = update_subject_phrase(title, summary, protocol)
    verb = update_lead_verb(title, summary, bool(summary))
    why = update_why_care(protocol, title, summary, tags)
    return f"{verb} {subject}. {why}"


def derived_meta(num: int, build: RFCBuild) -> RFCMeta:
    title = extract_title(build)
    tags = infer_tags(title, num)
    return RFCMeta(
        num,
        title,
        generate_update_chain_relevance(title, build, tags),
        tags,
        tuple(re.findall(r"[A-Za-z0-9][A-Za-z0-9-]{2,}", title.lower()))[:10],
        True,
    )


def expand_collection(max_depth: int = 2) -> tuple[list[RFCBuild], int]:
    builds: dict[int, RFCBuild] = {}
    queue: list[tuple[RFCMeta, int]] = [(meta, 0) for meta in RFCS]
    seed_nums = {meta.num for meta in RFCS}

    while queue:
        meta, depth = queue.pop(0)
        if meta.num in builds:
            continue
        build = fetch_one(meta, depth)
        if meta.update_chain:
            build.meta = derived_meta(meta.num, build)
        builds[meta.num] = build
        if depth >= max_depth:
            continue
        source = read_text(build.html_path) if build.html_ok else read_text(build.text_path)
        for related in sorted(parse_related_rfcs(source)):
            if related not in builds and all(queued.num != related for queued, _ in queue):
                placeholder = RFCMeta(related, f"RFC {related}", "", ("update-chain",), update_chain=True)
                queue.append((placeholder, depth + 1))

    ordered = [builds[meta.num] for meta in RFCS if meta.num in builds]
    ordered.extend(builds[num] for num in sorted(builds) if num not in seed_nums)
    return ordered, sum(1 for num in builds if num not in seed_nums)


def is_ascii_diagram_line(line: str) -> bool:
    trimmed = line.strip()
    if not trimmed:
        return False
    # bit numbers: 0 1 2 3 ...
    if re.fullmatch(r"(?:\d+\s+){6,}\d+", trimmed):
        return True
    # +---+ or |   | or +---+
    if re.fullmatch(r"[+|\-:\s]+", trimmed) and any(c in trimmed for c in "+|") and len(trimmed) >= 8:
        return True
    if re.search(r"\+[-+=]{3,}\+", trimmed):
        return True
    if re.search(r"\|.*\|", trimmed) and len(trimmed) >= 12:
        return True
    return False


def _clean_diagram_cell(c: str) -> str:
    """Strip leading/trailing box-drawing characters from a diagram cell."""
    c = re.sub(r'^[^A-Za-z0-9]*(?=[A-Za-z0-9])', '', c)
    c = re.sub(r'\s+[+\-=|]{2,}[\s+\-=|]*$', '', c).strip()
    return c


def render_modern_ascii_diagram(lines: list[str]) -> str:
    """Render ASCII diagrams using the enhanced diagram renderer.
    
    This function delegates to the diagram_renderer module which provides
    high-quality SVG-based visualizations for bit field diagrams, flow diagrams,
    and other technical ASCII art found in RFCs.
    """
    # Use the enhanced renderer from diagram_renderer module
    return diagram_renderer.render_modern_ascii_diagram_v2(lines)


def modernize_ascii_html(html_content: str, is_epub: bool = False) -> str:
    def pre_repl(match: re.Match[str]) -> str:
        pre_tag = match.group(1)
        pre_body = match.group(2)

        # Get raw text by stripping tags and unescaping
        raw_text = re.sub(r"<[^>]+>", "", pre_body)
        raw_text = html.unescape(raw_text)

        lines = raw_text.split("\n")
        parts = []
        index = 0
        changed = False

        while index < len(lines):
            if not is_ascii_diagram_line(lines[index]):
                start = index
                while index < len(lines) and not is_ascii_diagram_line(lines[index]):
                    index += 1
                text = "\n".join(lines[start:index])
                if text.strip():
                    parts.append({"type": "text", "content": text})
                continue

            start = index
            diagram_count = 0
            while index < len(lines) and (is_ascii_diagram_line(lines[index]) or not lines[index].strip()):
                if is_ascii_diagram_line(lines[index]):
                    diagram_count += 1
                index += 1

            block = lines[start:index]
            if diagram_count >= 3 and any(re.search(r"\|.*\||\+[-+=]{3,}\+", line) for line in block):
                parts.append({"type": "diagram", "lines": block})
                changed = True
            else:
                parts.append({"type": "text", "content": "\n".join(block)})

        if not changed:
            return match.group(0)

        result = []
        for part in parts:
            if part["type"] == "diagram":
                if is_epub:
                    result.append(render_modern_ascii_diagram(part["lines"]))
                else:
                    raw_ascii = "\n".join(part["lines"])
                    h = hashlib.sha256(raw_ascii.encode("utf-8")).hexdigest()
                    if h in DIAGRAM_CACHE:
                        mermaid_code = DIAGRAM_CACHE[h]
                        result.append(f'<div class="mermaid">\n{mermaid_code}\n</div>')
                    else:
                        result.append(render_modern_ascii_diagram(part["lines"]))
            else:
                content = part["content"].strip("\n")
                if content:
                    result.append(f"<pre>{html.escape(content)}</pre>")

        return "".join(result)

    return re.sub(r"(<pre[^>]*>)(.*?)(</pre>)", pre_repl, html_content, flags=re.S | re.I)



def extract_body(raw: str) -> str:
    match = re.search(r"<body[^>]*>(.*?)</body>", raw, flags=re.I | re.S)
    body = match.group(1) if match else raw
    body = re.sub(r"<script\b[^>]*>.*?</script>", "", body, flags=re.I | re.S)
    body = re.sub(r"<style\b[^>]*>.*?</style>", "", body, flags=re.I | re.S)
    body = re.sub(r"<link\b[^>]*>", "", body, flags=re.I)
    body = re.sub(r"\s(?:href|src)=[\"']https?://[^\"']+[\"']", "", body, flags=re.I)
    body = re.sub(r"\s(?:style|class|id)=[\"'][^\"']*[\"']", "", body, flags=re.I)
    return body.strip()


def read_text(path: Path | None) -> str:
    if not path:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def render_header_layout_svg(fields: list[tuple[str, int, str]]) -> str:
    """Render fields into 32-bit SVG rows with proportional blocks."""
    bit_px = 10
    label_h = 22
    row_h = 38
    width = 32 * bit_px
    segments: list[tuple[str, int, int, int]] = []
    row = 0
    cursor = 0
    for name, bit_width, _description in fields:
        remaining = bit_width
        while remaining > 0:
            take = min(remaining, 32 - cursor)
            segments.append((name, row, cursor, take))
            cursor += take
            remaining -= take
            if cursor == 32:
                row += 1
                cursor = 0
    rows = row + (1 if cursor else 0)
    height = label_h + max(rows, 1) * row_h + 8
    top_labels = "".join(
        f'<text x="{bit * bit_px}" y="14" class="bit-label">{bit}</text>'
        for bit in range(0, 32, 4)
    ) + f'<text x="{width}" y="14" text-anchor="end" class="bit-label">31</text>'
    grid_lines = "".join(
        f'<line x1="{bit * bit_px}" y1="{label_h}" x2="{bit * bit_px}" y2="{height - 8}" class="bit-grid" />'
        for bit in range(0, 33, 4)
    )
    blocks = []
    for index, (name, seg_row, start, span) in enumerate(segments):
        x = start * bit_px
        y = label_h + seg_row * row_h
        block_w = span * bit_px
        label = html.escape(name if span >= 8 else name[:3])
        continued = "" if sum(1 for seg in segments if seg[0] == name) == 1 else " segment"
        blocks.append(
            f'<g><rect x="{x}" y="{y}" width="{block_w}" height="{row_h - 4}" rx="7" class="field-block field-{index % 5}" />'
            f'<text x="{x + block_w / 2:.1f}" y="{y + 22}" text-anchor="middle" class="field-label">{label}</text>'
            f'<title>{html.escape(name)}: bits {start}-{start + span - 1} in row {seg_row + 1}{continued}</title></g>'
        )
    return (
        f'<svg class="header-bit-layout" viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="0-31 bit layout diagram" xmlns="http://www.w3.org/2000/svg">'
        f'<desc>0-31 bit positions across each row; fields are drawn as blocks spanning their bit widths.</desc>'
        f'{top_labels}{grid_lines}{"".join(blocks)}</svg>'
    )


def render_header_reference_panel(rfc_num: int) -> str:
    spec = HEADER_REFERENCES.get(rfc_num)
    if not spec:
        return ""
    fields = spec["fields"]
    assert isinstance(fields, list)
    svg = render_header_layout_svg(spec)

    rows = "".join(
        "<tr>"
        f"<td>{html.escape(name)}</td>"
        f"<td>{bit_width}</td>"
        f"<td>{html.escape(description)}</td>"
        "</tr>"
        for name, bit_width, description in fields
    )
    return f"""<details class=\"header-reference-panel\" open>
  <summary><span>Header field quick-reference</span><strong>{html.escape(str(spec["title"]))}</strong></summary>
  <p class=\"header-note\">{html.escape(str(spec["note"]))}</p>
  <div class=\"bit-axis\">Bit positions 0-31</div>
  <div class=\"header-diagram-wrap\">{svg}</div>
  <table class=\"header-field-table\">
    <thead><tr><th>Field</th><th>Bits</th><th>Hunting meaning / abnormal</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</details>"""


def render_detection_questions_panel(rfc_num: int) -> str:
    spec = HEADER_REFERENCES.get(rfc_num)
    if not spec:
        return ""
    questions = spec.get("detection_questions", [])
    if not isinstance(questions, list) or not questions:
        return ""
    items = "".join(f"<li>{html.escape(str(question))}</li>" for question in questions)
    return f"""<details class="detection-questions-panel">
  <summary><span>Detection prompts</span><strong>Questions to ask</strong></summary>
  <ol>{items}</ol>
</details>"""


def render_inline_header_reference(rfc_num: int) -> str:
    panel = render_header_reference_panel(rfc_num)
    return panel.replace(
        'class="header-reference-panel"',
        'class="header-reference-panel inline-header-reference"',
        1,
    )


def render_arp_receive_flow_chart() -> str:
    """Render RFC 826's packet-reception pseudo-code as a readable flow chart."""
    return """<section class=\"arp-flowchart-panel\" aria-labelledby=\"arp-flowchart-title\">
  <div class=\"arp-flowchart-kicker\">ARP receive state machine</div>
  <h2 id=\"arp-flowchart-title\">RFC 826 ARP Packet Reception Flow</h2>
  <p class=\"flow-subtitle\">The RFC intentionally updates sender mappings before checking whether the packet is a request. These decision cards make the hidden cache-poisoning logic visible.</p>
  <div class=\"arp-flow\" role=\"list\">
    <div class=\"flow-node start\" role=\"listitem\"><span class=\"flow-pill\">Receive</span><strong>ARP packet arrives</strong><small>Start with address-family sanity, not the opcode.</small></div>
    <div class=\"flow-arrow\">↓ validate hardware + protocol ↓</div>
    <div class=\"flow-node decision\" role=\"listitem\"><span class=\"flow-pill\">Decision</span><strong>Do I have the hardware type in ar$hrd?</strong><small>For Ethernet this should be <code>ares_hrd$Ethernet</code>; optionally verify <code>ar$hln</code>.</small></div>
    <div class=\"flow-node decision\" role=\"listitem\"><span class=\"flow-pill\">Decision</span><strong>Do I speak the protocol in ar$pro?</strong><small>For IPv4 ARP this should resolve the IP EtherType; optionally verify <code>ar$pln</code>.</small></div>
    <div class=\"flow-node stop\" role=\"listitem\"><span class=\"flow-pill\">No branch</span><strong>Discard / stop</strong><small>Negative conditionals end processing and drop the packet.</small></div>
    <div class=\"flow-node action\" role=\"listitem\"><span class=\"flow-pill\">Init</span><strong><code>Merge_flag := false</code></strong><small>Prepare to track whether an existing translation-table entry was refreshed.</small></div>
    <div class=\"flow-node merge\" role=\"listitem\"><span class=\"flow-pill\">Cache merge</span><strong>If <code>&lt;protocol type, sender protocol address&gt;</code> already exists, update sender hardware address and set <code>Merge_flag := true</code>.</strong><small>This is the poison-sensitive step: existing bindings may change before target/opcode checks.</small></div>
    <div class=\"flow-node decision\" role=\"listitem\"><span class=\"flow-pill\">Decision</span><strong>Am I the target protocol address?</strong><small>If not, the RFC flow stops after any merge/update above.</small></div>
    <div class=\"flow-node stop\" role=\"listitem\"><span class=\"flow-pill\">No branch</span><strong>Not my address: stop</strong><small>Translation-table side effects may already have happened if the sender pair matched.</small></div>
    <div class=\"flow-node action\" role=\"listitem\"><span class=\"flow-pill\">Learn</span><strong>If <code>Merge_flag</code> is false, add <code>&lt;protocol type, sender protocol address, sender hardware address&gt;</code>.</strong><small>Target hosts learn the sender before deciding whether to answer.</small></div>
    <div class=\"flow-node decision\" role=\"listitem\"><span class=\"flow-pill\">NOW</span><strong>NOW look at ar$op: is it <code>ares_op$REQUEST</code>?</strong><small>RFC 826 delays opcode inspection until after cache learning/merging.</small></div>
    <div class=\"flow-node stop\" role=\"listitem\"><span class=\"flow-pill\">No branch</span><strong>Not a request: stop</strong><small>Replies or unusual opcodes do not trigger reply construction here.</small></div>
    <div class=\"flow-node reply\" role=\"listitem\"><span class=\"flow-pill\">Reply build</span><strong>Swap hardware/protocol fields and put local addresses into sender fields.</strong><small>The original sender becomes the new target for the response.</small></div>
    <div class=\"flow-node reply\" role=\"listitem\"><span class=\"flow-pill\">Transmit</span><strong>Set ar$op = ares_op$REPLY and Send reply on the same hardware.</strong><small>Send to the new target hardware address on the interface that received the request.</small></div>
  </div>
</section>"""


ENHANCEMENT_REGISTRY: dict[int, list[tuple[str, object]]] = {
    768: [("Header Format\n\n", render_inline_header_reference)],
    791: [("Internet Header Format\n\n", render_inline_header_reference)],
    792: [("Message Formats\n\n", render_inline_header_reference)],
    793: [("TCP Header Format\n\n", render_inline_header_reference)],
    826: [
        ("Packet format:\n--------------\n", render_inline_header_reference),
        ("Packet Reception:\n-----------------\n\n", lambda _rfc_num: render_arp_receive_flow_chart()),
    ],
    1035: [("Header section format\n\n", render_inline_header_reference)],
    2131: [("Protocol Summary\n\n", render_inline_header_reference)],
    2460: [("IPv6 Header Format\n\n", render_inline_header_reference)],
    4271: [("BGP Message Header\n\n", render_inline_header_reference)],
    4303: [("Encapsulating Security Payload Packet Format\n\n", render_inline_header_reference)],
}


def inject_all_enhancements(rfc_num: int, body: str) -> tuple[str, set[str]]:
    """Place registered protocol enhancements next to the RFC prose they explain."""
    inserted: set[str] = set()
    for anchor, render_fn in ENHANCEMENT_REGISTRY.get(rfc_num, []):
        if anchor not in body:
            continue
        enhancement = render_fn(rfc_num)  # type: ignore[operator]
        if not enhancement:
            continue
        body = body.replace(anchor, f"{anchor}</pre>{enhancement}<pre>", 1)
        inserted.add(getattr(render_fn, "__name__", "enhancement"))
    return body, inserted


def inject_inline_header_reference(rfc_num: int, body: str) -> tuple[str, bool]:
    updated, inserted = inject_all_enhancements(rfc_num, body)
    return updated, "render_inline_header_reference" in inserted


def inject_arp_receive_flow_chart(rfc_num: int, body: str) -> tuple[str, bool]:
    updated, inserted = inject_all_enhancements(rfc_num, body)
    return updated, "<lambda>" in inserted


def markup_text_content(markup: str) -> str:
    text = re.sub(r"<[^>]+>", " ", markup)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def classify_source_page_label(index: int, page_text: str) -> str:
    lowered = page_text.lower()
    if index == 0:
        return "Cover page"
    if "table of contents" in lowered:
        return "Contents"
    if "appendix" in lowered and "glossary" not in lowered:
        return "Appendix"
    if "references" in lowered and len(page_text) < 240:
        return "References"
    return f"Source page {index + 1}"


def normalize_source_page_markup(page_markup: str) -> str:
    page_markup = page_markup.strip()
    if not page_markup:
        return ""
    match = re.match(r"(?s)(.*?)(<pre\b.*)", page_markup)
    if not match or not match.group(1).strip():
        return page_markup
    lead = re.sub(r"(?:<br\s*/?>\s*){3,}", "<br />", match.group(1).strip(), flags=re.I)
    return f'<div class="rfc-page-meta">{lead}</div>{match.group(2)}'


def format_rfc_source_body(body: str, source_format: str) -> str:
    raw_pages = re.split(r"<hr\s*/?>\s*<!--NewPage-->", body, flags=re.I)
    page_markup: list[str] = []
    for raw_page in raw_pages:
        text = markup_text_content(raw_page)
        if not text:
            continue
        index = len(page_markup)
        label = classify_source_page_label(index, text)
        page_class = "rfc-page"
        if index == 0:
            page_class += " is-cover"
        if "table of contents" in text.lower():
            page_class += " is-contents"
        page_markup.append(
            f"""<section class="{page_class}">
  <div class="rfc-page-top">
    <span class="rfc-page-label">{label}</span>
  </div>
  {normalize_source_page_markup(raw_page)}
</section>"""
        )

    if not page_markup:
        page_markup.append(
            """<section class="rfc-page is-cover">
  <div class="rfc-page-top">
    <span class="rfc-page-label">Source page 1</span>
  </div>
  <pre>RFC source could not be formatted.</pre>
</section>"""
        )

    page_count = len(page_markup)
    page_label = "1 page card" if page_count == 1 else f"{page_count} page cards"
    return f"""<div class="source-banner">
  <div>
    <span class="source-kicker">Reader mode</span>
    <strong>Original RFC text, but with fewer cold-war fax vibes.</strong>
    <p>The source is still the source. We just gave it page cards, local links, and enough breathing room that your eyeballs no longer need hazard pay.</p>
  </div>
  <div class="source-meta">
    <span class="source-chip">{page_label}</span>
    <span class="source-chip">{html.escape(source_format)}</span>
    <span class="source-chip">Page breaks preserved</span>
  </div>
</div>
<div class="rfc-source-shell">
  {''.join(page_markup)}
</div>"""


def page(title: str, content: str, extra_head: str = "") -> str:
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>{html.escape(title)}</title>
  <link rel=\"stylesheet\" href=\"{extra_head}assets/style.css\">
  <script type="module">import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs'; mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});</script>
</head>
<body>
<a class="skip-link" href="#main-content">Skip to main content</a>
{content}
</body>
</html>
"""



def rfc_href(num: int, local_nums: set[int], local_prefix: str = "", local_ext: str = ".html") -> tuple[str, str]:
    if num in local_nums:
        return f"{local_prefix}rfc{num}{local_ext}", "rfc-local"
    return f"https://www.rfc-editor.org/rfc/rfc{num}.html", "rfc-external"


def rewrite_anchor_links(markup: str, local_nums: set[int], local_prefix: str = "", local_ext: str = ".html") -> str:
    def repl(match: re.Match[str]) -> str:
        attrs, label = match.group(1), match.group(3)
        num_match = re.search(r"(?:/|\.)rfc(\d{3,5})(?:\D|$)", attrs, flags=re.I)
        if not num_match:
            return match.group(0)
        num = int(num_match.group(1))
        href, css_class = rfc_href(num, local_nums, local_prefix, local_ext)
        return f'<a href="{href}" class="{css_class}">{label}</a>'

    return re.sub(r"<a\b([^>]*)>(\s*(\d{3,5})\s*)</a>", repl, markup, flags=re.I)


def link_plain_metadata_refs(escaped_text: str, local_nums: set[int], local_prefix: str = "", local_ext: str = ".html") -> str:
    def line_repl(match: re.Match[str]) -> str:
        label, rest = match.group(1), match.group(2)

        def num_repl(num_match: re.Match[str]) -> str:
            prefix = num_match.group(1) or ""
            num = int(num_match.group(2))
            href, css_class = rfc_href(num, local_nums, local_prefix, local_ext)
            return f'{prefix}<a href="{href}" class="{css_class}">{num}</a>'

        linked = re.sub(r"\b(RFCs?\s*)?(\d{3,5})\b", num_repl, rest, flags=re.I)
        return f"{label}{linked}"

    return re.sub(r"\b(Updated by:|Obsoletes:|Obsoleted by:)([^\n]*)", line_repl, escaped_text, flags=re.I)


def localize_rfc_links(markup: str, local_nums: set[int], local_prefix: str = "", local_ext: str = ".html") -> str:
    return rewrite_anchor_links(markup, local_nums, local_prefix, local_ext)


def render_threat_indicators(rfc_num: int) -> str:
    indicators = THREAT_INDICATORS.get(rfc_num)
    if not indicators:
        return ""
    
    items = []
    for index, ind in enumerate(indicators):
        items.append(f"""
    <div class="threat-item" id="threat-{index + 1}">
      <div class="threat-header">
        <span class="threat-name">{html.escape(ind["name"])}</span>
        <span class="threat-severity sev-{ind["sev"]}">{html.escape(ind["sev"])}</span>
      </div>
      <div class="threat-details">
        <div class="threat-box threat-normal">
          <span class="threat-box-label">Normal behavior</span>
          {html.escape(ind["normal"])}
        </div>
        <div class="threat-box threat-malicious">
          <span class="threat-box-label">Malicious indicator</span>
          {html.escape(ind["malicious"])}
        </div>
      </div>
    </div>""")
    
    return f"""<details class="threat-panel" open>
  <summary><span>Hunting context</span><strong>Threat Indicators</strong></summary>
  <div class="threat-list">
    {''.join(items)}
  </div>
</details>"""


def generate_flashcards(builds: list[RFCBuild]) -> list[dict[str, str]]:
    cards = []
    for build in builds:
        num = build.meta.num
        # Fundamentals
        cards.append({
            "id": f"rfc-{num}-fundamental",
            "rfc": str(num),
            "category": "Protocol Fundamentals",
            "prompt": f"What is the primary function and layer of RFC {num} ({build.meta.title})?",
            "answer": f"Layer: {', '.join(build.meta.tags)}\n\nFunction: {build.meta.relevance}"
        })
        
        # Header Fields
        header = HEADER_REFERENCES.get(num)
        if header:
            for field_name, bit_width, purpose in header["fields"]:
                cards.append({
                    "id": f"rfc-{num}-header-{field_name.lower().replace(' ', '-')}",
                    "rfc": str(num),
                    "category": f"Header Field: {field_name}",
                    "prompt": f"In RFC {num} ({header['title']}), what is the purpose and bit-width of the '{field_name}' field?",
                    "answer": f"Bit-width: {bit_width} bits\n\nPurpose: {purpose}"
                })
        
        # Threat Indicators
        threats = THREAT_INDICATORS.get(num)
        if threats:
            for i, ind in enumerate(threats):
                cards.append({
                    "id": f"rfc-{num}-threat-{i}",
                    "rfc": str(num),
                    "category": "Threat Indicator",
                    "prompt": f"RFC {num}: What are the malicious indicators for '{ind['name']}'?",
                    "answer": f"Severity: {ind['sev'].upper()}\n\nNormal: {ind['normal']}\n\nMalicious: {ind['malicious']}"
                })
    return cards


def render_study_overlay() -> str:
    return """<div id="study-overlay" class="study-overlay">
  <div class="study-progress-bar" id="study-progress-bar"></div>
  <div class="study-header">
    <span id="study-count">Card 1 of 10</span>
    <span id="study-timer">00:00</span>
    <div style="display:flex; gap:10px;">
      <button id="reset-srs" class="reader-btn" style="border-color:var(--pink); color:var(--pink);">Reset Progress</button>
      <button id="close-study" class="reader-btn">Exit (Esc)</button>
    </div>
  </div>
  
  <div id="card-container" class="card-container">
    <div class="flashcard">
      <div class="card-face card-front">
        <div class="card-category" id="card-category">CATEGORY</div>
        <div class="card-prompt" id="card-prompt">Prompt text?</div>
        <div class="study-hint">Click or Space to flip</div>
      </div>
      <div class="card-face card-back">
        <div class="card-category" id="card-category-back">CATEGORY</div>
        <div class="card-answer" id="card-answer">Answer text.</div>
        <div class="card-meta" id="card-meta">S: 0 | D: 0 | R: 0%</div>
      </div>
    </div>
  </div>

  <div id="study-actions" class="study-actions">
    <button class="srs-btn btn-again" data-quality="1">Again (1)</button>
    <button class="srs-btn btn-hard" data-quality="2">Hard (2)</button>
    <button class="srs-btn btn-good" data-quality="3">Good (3)</button>
    <button class="srs-btn btn-easy" data-quality="4">Easy (4)</button>
  </div>

  <div id="study-summary" class="study-summary">
    <h1>Session Complete!</h1>
    <div class="summary-grid">
      <div class="summary-stat"><b id="sum-reviewed">0</b>Reviewed</div>
      <div class="summary-stat"><b id="sum-mastered">0</b>Mastered</div>
      <div class="summary-stat"><b id="sum-due">0</b>Due Tomorrow</div>
    </div>
    <div style="display:flex; gap:15px; justify-content:center;">
      <button id="restart-study" class="reader-btn">Study Again</button>
      <button id="finish-study" class="reader-btn">Finish</button>
    </div>
  </div>
</div>"""


def render_map_overlay() -> str:
    return """
<div id="map-overlay" class="map-overlay" role="dialog" aria-modal="true" aria-label="Interactive RFC graph" aria-hidden="true">
  <div class="map-header">
    <div class="eyebrow">Interactive RFC Graph</div>
    <div class="inline-actions">
      <button id="close-map" class="reader-btn" type="button">Exit Map (Esc)</button>
    </div>
  </div>
  <div id="map-container" class="map-container">
    <div class="map-legend">
      <div class="legend-group">
        <h4>Layers</h4>
        <div class="legend-item"><div class="legend-color" style="background:var(--violet)"></div> Link</div>
        <div class="legend-item"><div class="legend-color" style="background:var(--cyan)"></div> Network/Routing</div>
        <div class="legend-item"><div class="legend-color" style="background:var(--amber)"></div> Transport</div>
        <div class="legend-item"><div class="legend-color" style="background:var(--pink)"></div> Application</div>
        <div class="legend-item"><div class="legend-color" style="background:var(--green)"></div> Monitoring</div>
      </div>
      <div class="legend-group">
        <h4>Relationships</h4>
        <div class="legend-item"><div class="legend-line" style="background:var(--text)"></div> Dependency</div>
        <div class="legend-item"><div class="legend-line" style="border-top:2px dashed var(--amber)"></div> Update Chain</div>
        <div class="legend-item"><div class="legend-line" style="border-top:2px dotted var(--pink)"></div> Threat Link</div>
      </div>
    </div>
  </div>
</div>
"""


def render_study_plan() -> str:
    track_cards = []
    for track in STUDY_TRACKS:
        rfcs = track["rfcs"]
        chips = "".join(f"<span class=\"study-chip\">RFC {num}</span>" for num in rfcs)
        rfc_values = " ".join(str(num) for num in rfcs)
        track_cards.append(
            f"""<article class="study-track">
  <div class="study-track-head">
    <span class="study-track-kicker">{html.escape(track["eyebrow"])}</span>
    <h3>{html.escape(track["title"])}</h3>
  </div>
  <p>{html.escape(track["summary"])}</p>
  <div class="study-chip-row">{chips}</div>
  <button class="reader-btn style-cyan study-path-btn" type="button" data-path="{html.escape(track["id"])}" data-label="{html.escape(track["title"])}" data-rfcs="{html.escape(rfc_values)}">Load this path</button>
</article>"""
        )

    science_items = "".join(
        f"""<li><a href="{html.escape(note["url"])}">{html.escape(note["title"])}</a><span>{html.escape(note["source"])} · {html.escape(note["summary"])}</span></li>"""
        for note in SCIENCE_NOTES
    )

    return f"""<section id="study-plan" class="study-plan">
  <div class="study-plan-intro">
    <div class="eyebrow">Science-backed study plan</div>
    <h2>Study like a hunter, not a hostage.</h2>
    <p>You do not need to absorb 228 RFCs in one tragic caffeine opera. The research-backed move is smaller: pick a mission, read one meaningful chunk, try to recall it from memory, and let spaced review do the heavy lifting while your ego takes a brief but educational hit.</p>
  </div>

  <div class="study-plan-grid">
    <article class="study-card">
      <span class="study-card-kicker">Daily loop</span>
      <h3>The 25-minute orbit</h3>
      <ol class="study-list">
        <li><strong>2 minutes:</strong> Pick one track and skim the hunting context so your brain knows why this RFC matters.</li>
        <li><strong>12 minutes:</strong> Read one RFC or one major section. Stop before fatigue turns prose into wallpaper.</li>
        <li><strong>4 minutes:</strong> Close the page and write or say three things you remember. No peeking. Mild annoyance means it is working.</li>
        <li><strong>5 minutes:</strong> Run <em>Study Due</em> for low-stakes retrieval with feedback.</li>
        <li><strong>2 minutes:</strong> Leave one note: weird field, likely detection clue, or one thing Future You will forget on purpose.</li>
      </ol>
    </article>

    <article class="study-card">
      <span class="study-card-kicker">Weekly rhythm</span>
      <h3>How to not bounce off the material</h3>
      <ul class="study-list">
        <li><strong>Four focused sessions:</strong> Stay inside one sprint so the protocol family starts to cohere.</li>
        <li><strong>One mixed session:</strong> Use the protocol map plus due cards to interleave concepts and dependencies.</li>
        <li><strong>One light day:</strong> Catch up, reread a threat indicator, or take a guilt-free rest day. Sustainability beats martyrdom.</li>
      </ul>
      <p class="study-aside">After the six core sprints, use the <strong>update-chain</strong> tag as your side-quest generator.</p>
    </article>

    <article class="study-card planner-card">
      <span class="study-card-kicker">Implementation intention</span>
      <h3>Make Future You dramatically less slippery</h3>
      <p>If-then plans help turn vague good intentions into visible action. Keep the cue specific and the task tiny enough that your internal gremlin has a weaker legal case.</p>
      <div class="if-then-form">
        <label>
          <span>If it is...</span>
          <input id="if-then-cue" type="text" placeholder="after coffee, after standup, 8:30 PM">
        </label>
        <label>
          <span>Then I will...</span>
          <input id="if-then-action" type="text" placeholder="read one RFC section and do 10 due cards">
        </label>
        <div id="if-then-preview" class="if-then-preview">If your cue happens, then your study move lives here. Tiny counts. Tiny is how empires are built.</div>
        <div class="inline-actions">
          <button id="save-if-then" class="reader-btn style-cyan" type="button">Save pact</button>
          <button id="clear-if-then" class="reader-btn" type="button">Clear pact</button>
        </div>
        <div id="if-then-status" class="study-status" aria-live="polite"></div>
      </div>
    </article>
  </div>

  <div class="study-status-row">
    <div class="study-active">
      <span class="study-card-kicker">Current focus</span>
      <strong id="active-study-path">Full library mode</strong>
      <span>Load a track to narrow the grid to a sane starting point.</span>
    </div>
    <button id="clear-study-path" class="reader-btn" type="button">Show whole library</button>
  </div>

  <div class="study-track-grid">
    {''.join(track_cards)}
  </div>

  <article class="study-card evidence-card">
    <span class="study-card-kicker">Evidence, not vibes</span>
    <h3>Why this routine works</h3>
    <ul class="science-list">
      {science_items}
    </ul>
  </article>
</section>"""


def build_site(builds: list[RFCBuild]) -> None:
    if SITE_DIR.exists():
        shutil.rmtree(SITE_DIR)
    (SITE_DIR / "rfc").mkdir(parents=True)
    (SITE_DIR / "assets").mkdir(parents=True)
    (SITE_DIR / "assets" / "style.css").write_text(SITE_CSS, encoding="utf-8")
    (SITE_DIR / "assets" / "index.js").write_text(INDEX_JS, encoding="utf-8")
    (SITE_DIR / "assets" / "doc.js").write_text(DOC_JS, encoding="utf-8")

    local_nums = {build.meta.num for build in builds}
    all_tags = sorted({tag for build in builds for tag in build.meta.tags})
    flashcards = generate_flashcards(builds)
    
    study_overlay = render_study_overlay()
    map_overlay = render_map_overlay()
    study_plan = render_study_plan()
    
    filters = ["<button class=\"filter active\" data-tag=\"all\">All</button>"]
    filters.extend(f"<button class=\"filter\" data-tag=\"{html.escape(tag)}\">{html.escape(tag)}</button>" for tag in all_tags)
    
    stats = "".join(
        f"<div class=\"stat\"><b>{sum(tag in build.meta.tags for build in builds)}</b><span>{html.escape(tag)}<br>{html.escape(TAG_DESCRIPTIONS[tag])}</span></div>"
        for tag in all_tags
    )
    # Add SRS progress card
    stats += """<div class="stat study-progress-card">
      <b id="srs-due-count">0</b>
      <span>Due Today<br>Cards ready for spaced repetition review.</span>
      <div class="btn-group">
        <button id="start-study" class="reader-btn">Study Due</button>
        <button id="study-all" class="reader-btn">Study All</button>
        <button id="open-map" class="reader-btn style-pink" type="button">Protocol Map</button>
      </div>
    </div>"""

    cards = []
    for build in builds:
        meta = build.meta
        search = " ".join([str(meta.num), meta.title, meta.relevance, " ".join(meta.tags), " ".join(meta.keywords)]).lower()
        tags = "".join(f"<span class=\"tag tag-{html.escape(tag)}\">{html.escape(tag)}</span>" for tag in meta.tags)
        status = "HTML" if build.html_ok else "TXT" if build.text_ok else "missing"
        card_class = "card chain" if meta.update_chain else "card"
        cards.append(
            f"""<a class=\"{card_class}\" href=\"rfc/{slug(meta)}\" data-search=\"{html.escape(search)}\" data-tags=\"{html.escape(' '.join(meta.tags))}\" data-rfc=\"{meta.num}\">
  <span class=\"num\">RFC {meta.num} · {status}</span>
  <h2>{html.escape(meta.title)}</h2>
  <p>{html.escape(meta.relevance)}</p>
  <div class=\"tags\">{tags}</div>
  <span class=\"open\">Read chapter</span>
</a>"""
        )

    index_content = f"""
{study_overlay}
{map_overlay}
<script>window.FLASHCARDS = {flashcards};</script>
<header class=\"hero shell\">
  <div class=\"eyebrow\">Curated protocol intelligence</div>
  <h1>RFCs for network threat hunting.</h1>
  <p><strong>{len(builds)} specifications</strong> covering transport, routing, monitoring, security, application-layer behavior, and two-hop update-chain context. Built as a fully local dark-mode reference library with guided study tracks, spaced review, and no runtime network dependencies.</p>
  <div class=\"hero-actions\" aria-label=\"Primary actions\">
    <a class=\"hero-action\" href=\"#study-plan\">Start a study plan</a>
    <a class=\"hero-action primary\" href=\"#rfc-grid\">Browse RFCs</a>
    <button id=\"view-notes\" class=\"hero-action\" type=\"button\">View notes</button>
  </div>
</header>
<div class=\"toolbar\"><div class=\"shell\"><div class=\"toolbar-row\"><label class=\"searchbox\"><span aria-hidden=\"true\">⌕</span><input id=\"q\" autocomplete=\"off\" placeholder=\"Filter by RFC number, title, tag, or keyword...\" aria-label=\"Filter RFCs\"></label><div class=\"toolbar-controls\"><div id=\"count\" class=\"view-count\" aria-live=\"polite\"></div><button id=\"density-toggle\" class=\"reader-btn\" type=\"button\">Compact cards</button></div></div><div class=\"filters\" aria-label=\"Protocol category filters\">{''.join(filters)}</div></div></div>
<main id=\"main-content\" class=\"shell\">
  {study_plan}
  <section class=\"stats\">{stats}</section>
  <section id=\"rfc-grid\" class=\"grid\">{''.join(cards)}</section>
  <p class=\"empty\">No matching RFCs. Try a protocol name, tag, or RFC number.</p>
</main>
<section id=\"notes-view\" class=\"notes-view shell\" aria-live=\"polite\">
  <div class=\"notes-header\">
    <div>
      <div class=\"eyebrow\">Local annotations</div>
      <h2>Your saved RFC notes</h2>
      <p>Review highlights, evidence ideas, and hunting notes saved in this browser.</p>
    </div>
    <div class=\"btn-group\">
      <button id=\"back-to-grid\" class=\"reader-btn\" type=\"button\">Back to RFCs</button>
      <button id=\"export-notes\" class=\"reader-btn\" type=\"button\">Export notes</button>
      <button id=\"import-notes-btn\" class=\"reader-btn\" type=\"button\">Import notes</button>
      <input id=\"import-notes-file\" type=\"file\" accept=\"application/json\" hidden>
    </div>
  </div>
  <div class=\"notes-filter-row\" aria-label=\"Note type filters\">
    <button class=\"notes-filter-btn active\" data-filter=\"all\" type=\"button\">All</button>
    <button class=\"notes-filter-btn\" data-filter=\"note\" type=\"button\">Notes</button>
    <button class=\"notes-filter-btn\" data-filter=\"highlight\" type=\"button\">Highlights</button>
  </div>
  <div id=\"notes-container\"></div>
</section>
<footer><div class=\"shell\">Generated locally from rfc-editor.org sources. Open an RFC card to read the cached HTML source or styled plaintext fallback.</div></footer>
<script src=\"assets/index.js\"></script>
"""
    (SITE_DIR / "index.html").write_text(page("RFC Threat Hunting Library", index_content), encoding="utf-8")

    for build in builds:
        meta = build.meta
        tags = "".join(f"<span class=\"tag tag-{html.escape(tag)}\">{html.escape(tag)}</span>" for tag in meta.tags)
        inline_header_reference = False
        if build.html_ok and build.html_path:
            body = localize_rfc_links(extract_body(read_text(build.html_path)), local_nums)
            body = modernize_ascii_html(body)
            body, inserted_enhancements = inject_all_enhancements(meta.num, body)
            inline_header_reference = "render_inline_header_reference" in inserted_enhancements
            body = format_rfc_source_body(body, "RFC Editor HTML")
        elif build.text_ok and build.text_path:
            linked_text = link_plain_metadata_refs(html.escape(read_text(build.text_path)), local_nums)
            body = modernize_ascii_html(f"<pre>{linked_text}</pre>")
            body, inserted_enhancements = inject_all_enhancements(meta.num, body)
            inline_header_reference = "render_inline_header_reference" in inserted_enhancements
            body = format_rfc_source_body(body, "Plaintext fallback")
        else:
            body = format_rfc_source_body("<pre>RFC source could not be fetched.</pre>", "Unavailable source")
        header_reference = "" if inline_header_reference else render_header_reference_panel(meta.num)
        detection_questions = render_detection_questions_panel(meta.num)
        threat_indicators = render_threat_indicators(meta.num)
        content = f"""
<div class=\"progress\"></div>
{study_overlay}
<script>window.FLASHCARDS = {flashcards};</script>
<main id=\"main-content\" class=\"doc-layout\">
  <a class=\"toplink\" href=\"../index.html\">← Back to index</a>
  <section class=\"doc-hero\">
    <div class=\"eyebrow\">RFC {meta.num}</div>
    <h1>{html.escape(meta.title)}</h1>
    <div class=\"meta-tags\">{tags}</div>
    <div class=\"note\"><strong>Threat hunting relevance:</strong> {html.escape(meta.relevance)}</div>
  </section>
  <section class=\"reader-tools\">
    <div class=\"group\">
        <button class=\"reader-btn\" data-action=\"focus\">Focus width</button>
        <button class=\"reader-btn\" data-action=\"comfy\">Comfy text</button>
        <button id=\"study-rfc\" class=\"reader-btn\">Study this RFC <span id=\"study-badge\" class=\"badge\"></span></button>
    </div>
    <button class=\"reader-btn\" data-action=\"top\">Back to top</button>
  </section>
  <section class=\"reader-grid\"><article class=\"doc-body\">{body}</article><aside class=\"toc-panel\">{detection_questions}{threat_indicators}{header_reference}<h2>On this RFC</h2><div id=\"toc-links\"></div></aside></section>
</main>
<script src=\"../assets/doc.js\"></script>
"""
        (SITE_DIR / "rfc" / slug(meta)).write_text(page(f"RFC {meta.num}: {meta.title}", content, "../"), encoding="utf-8")


def plain_to_xhtml(text: str) -> str:
    return f"<pre>{html.escape(text)}</pre>"


def html_to_epub_xhtml(raw: str) -> str:
    body = extract_body(raw)
    body = re.sub(r"<script\b[^>]*>.*?</script>", "", body, flags=re.I | re.S)
    body = re.sub(r"<style\b[^>]*>.*?</style>", "", body, flags=re.I | re.S)
    body = re.sub(r"\s(?:onclick|onload|onerror|style)=([\"']).*?\1", "", body, flags=re.I | re.S)
    body = re.sub(r"<br\s*>", "<br />", body, flags=re.I)
    body = re.sub(r"<hr\s*>", "<hr />", body, flags=re.I)
    return body


def epub_chapter_file(num: int) -> str:
    return f"rfc{num}.xhtml"


def tag_list(tags: Iterable[str]) -> str:
    return "".join(f'<span class="tag">{html.escape(tag)}</span>' for tag in tags)


def render_inline_study_checkpoint(build: RFCBuild, limit: int = 3) -> str:
    cards = generate_flashcards([build])[:limit]
    if not cards:
        return ""
    items = "".join(
        f"""<li><p><strong>{html.escape(card['prompt'])}</strong></p><p class="answer">{html.escape(card['answer']).replace(chr(10), '<br />')}</p></li>"""
        for card in cards
    )
    return f"""<div class="checkpoint"><p class="kicker">Study checkpoint</p><h2>Quick review: RFC {build.meta.num}</h2><ol>{items}</ol></div>"""


def chapter_content(build: RFCBuild, local_nums: set[int], include_category: bool = False) -> str:
    meta = build.meta
    if build.html_ok and build.html_path:
        source = localize_rfc_links(html_to_epub_xhtml(read_text(build.html_path)), local_nums, local_ext=".xhtml")
        source = modernize_ascii_html(source, is_epub=True)
    elif build.text_ok and build.text_path:
        linked_text = link_plain_metadata_refs(html.escape(read_text(build.text_path)), local_nums, local_ext=".xhtml")
        source = modernize_ascii_html(f"<pre>{linked_text}</pre>", is_epub=True)
    else:
        source = "<p>RFC source could not be fetched.</p>"

    category = f"<p><strong>Categories:</strong> {html.escape(', '.join(meta.tags))}</p>" if include_category else ""
    keywords = f"<p><strong>Keywords:</strong> {html.escape(', '.join(meta.keywords))}</p>" if meta.keywords else ""
    seed_note = "Update-chain context" if meta.update_chain else "Seed RFC"
    header_reference = render_header_reference_panel(meta.num)
    detection_questions = render_detection_questions_panel(meta.num)
    threat_indicators = render_threat_indicators(meta.num)
    return f"""<h1>RFC {meta.num}: {html.escape(meta.title)}</h1>
<aside class="chapter-brief">
  <p class="kicker">{html.escape(seed_note)}</p>
  <p><strong>Threat hunting relevance:</strong> {html.escape(meta.relevance)}</p>
  {category}
  {keywords}
  <p class="tags">{tag_list(meta.tags)}</p>
</aside>
{detection_questions}
{threat_indicators}
{header_reference}
{source}
{render_inline_study_checkpoint(build)}
"""


def add_epub_css(book: epub.EpubBook) -> epub.EpubItem:
    css = """
body { font-family: Georgia, serif; line-height: 1.62; color: #111827; margin: 0 5%; }
h1 { color: #0f172a; font-size: 1.85em; line-height: 1.08; border-bottom: 2px solid #dbeafe; padding-bottom: .35em; }
h2, h3, h4 { color: #172554; margin-top: 1.4em; }
aside, .chapter-brief, .category-card, .threat-panel, .header-reference-panel, .detection-questions-panel { border-left: 5px solid #2563eb; background: #eef5ff; padding: .8em 1em; margin: 1em 0 1.25em; border-radius: .35em; }
pre { white-space: pre-wrap; font-family: ui-monospace, Consolas, monospace; font-size: .82em; line-height: 1.45; background: #f8fafc; border: 1px solid #e2e8f0; padding: .8em; }
table { border-collapse: collapse; width: 100%; margin: 1em 0; }
th, td { border: 1px solid #cbd5e1; padding: .35em .45em; vertical-align: top; }
th { background: #dbeafe; color: #172554; }
a { color: #1d4ed8; }
a.rfc-local { color: #047857; font-weight: bold; }
a.rfc-external { color: #b45309; font-weight: bold; }
ul.index-list { padding-left: 1.2em; }
ul.index-list li { margin: .45em 0; }
.kicker { color: #2563eb; font-family: sans-serif; font-size: .78em; font-weight: bold; letter-spacing: .12em; text-transform: uppercase; }
.title-page { margin-top: 18%; text-align: center; }
.title-page h1 { border: 0; font-size: 2.4em; }
.title-page p, .muted { color: #475569; }
.tags { margin-top: .75em; }
.tag { display: inline-block; border: 1px solid #bfdbfe; border-radius: 999px; padding: .12em .55em; margin: .1em .2em .1em 0; color: #1e3a8a; background: #eff6ff; font-family: sans-serif; font-size: .78em; font-weight: bold; }
.threat-item, .field-card { border-top: 1px solid #bfdbfe; padding-top: .75em; margin-top: .75em; }
.threat-severity { font-family: sans-serif; font-size: .75em; font-weight: bold; text-transform: uppercase; color: #991b1b; }
.header-bit-grid, .flow-lane, .flow-node { display: block; }
.field-purpose, .threat-box, .flow-node small { color: #334155; }
.learning-svg { display: block; width: 100%; max-width: 760px; height: auto; margin: 1.2em auto; }
.svg-label { font-family: sans-serif; font-size: 15px; font-weight: bold; fill: #0f172a; }
.svg-small { font-family: sans-serif; font-size: 11px; fill: #334155; }
.checkpoint { border: 1px solid #bfdbfe; background: #f8fafc; padding: .8em 1em; margin: 1em 0; border-radius: .4em; }
.answer { color: #334155; margin-top: .25em; }
.modern-ascii-diagram { padding: 1.2em; border: 1px solid #cbd5e1; border-radius: .8em; background: #f1f5f9; margin: 1.2em 0; }
.modern-diagram-kicker { font-size: .75em; font-weight: bold; text-transform: uppercase; color: #475569; margin-bottom: .8em; display: block; }
.modern-diagram-grid { display: block; }
.modern-diagram-row { display: table; width: 100%; table-layout: fixed; border-collapse: separate; border-spacing: 4px; }
.modern-diagram-cell { display: table-cell; padding: .5em; border: 1px solid #94a3b8; border-radius: .4em; background: #fff; text-align: center; vertical-align: middle; font-size: .8em; font-weight: bold; }
.modern-diagram-fallback { white-space: pre-wrap; font-family: monospace; font-size: .85em; }
"""
    nav_css = epub.EpubItem(uid="style_nav", file_name="style/nav.css", media_type="text/css", content=css)
    book.add_item(nav_css)
    return nav_css


def make_book(title: str, identifier: str) -> epub.EpubBook:
    book = epub.EpubBook()
    book.set_identifier(identifier)
    book.set_title(title)
    book.set_language("en")
    book.add_author("RFC Editor; curated locally for network threat hunting")
    add_epub_css(book)
    return book


def make_intro(book: epub.EpubBook, title: str, subtitle: str) -> epub.EpubHtml:
    intro = epub.EpubHtml(title="Introduction", file_name="intro.xhtml", lang="en")
    intro.content = f"""<section class=\"title-page\">
<p class=\"kicker\">Network Threat Hunting Reference</p>
<h1>{html.escape(title)}</h1>
<p>{html.escape(subtitle)}</p>
<p>Each chapter opens with a short analyst note explaining why the protocol matters during hunting and investigation.</p>
</section>"""
    intro.add_item(book.get_item_with_id("style_nav"))
    book.add_item(intro)
    return intro


def category_chart_svg(builds: list[RFCBuild]) -> str:
    counts = [(tag, sum(tag in build.meta.tags for build in builds)) for tag in TAG_DESCRIPTIONS]
    max_count = max(count for _, count in counts) or 1
    rows = []
    for index, (tag, count) in enumerate(counts):
        y = 42 + index * 42
        width = 430 * count / max_count
        rows.append(f"""
  <text class="svg-label" x="18" y="{y + 16}">{html.escape(tag.title())}</text>
  <rect x="155" y="{y}" width="{width:.1f}" height="24" rx="12" fill="#2563eb" opacity=".86" />
  <text class="svg-small" x="{165 + width:.1f}" y="{y + 16}">{count} RFCs</text>""")
    return f"""<svg class="learning-svg" viewBox="0 0 660 310" role="img" aria-label="RFC category distribution" xmlns="http://www.w3.org/2000/svg">
  <rect width="660" height="310" rx="22" fill="#eff6ff" />
  <text class="svg-label" x="18" y="28">Category Coverage</text>
  {''.join(rows)}
</svg>"""


def protocol_stack_svg() -> str:
    layers = [
        ("Application", "DNS · DHCP · SMTP · HTTP", "#db2777"),
        ("Monitoring", "NetFlow · IPFIX · flow telemetry", "#0891b2"),
        ("Transport", "UDP · TCP · HTTP/2 framing context", "#d97706"),
        ("Routing", "IPv4 · IPv6 · ICMP · ARP · OSPF · BGP", "#7c3aed"),
        ("Security", "IPsec · ESP · DNSSEC · protocol abuse", "#059669"),
    ]
    rows = []
    for index, (name, examples, color) in enumerate(layers):
        y = 34 + index * 58
        rows.append(f"""
  <rect x="34" y="{y}" width="592" height="42" rx="16" fill="{color}" opacity=".86" />
  <text class="svg-label" x="55" y="{y + 25}" fill="#ffffff">{html.escape(name)}</text>
  <text class="svg-small" x="185" y="{y + 25}" fill="#ffffff">{html.escape(examples)}</text>""")
    return f"""<svg class="learning-svg" viewBox="0 0 660 340" role="img" aria-label="Protocol learning stack" xmlns="http://www.w3.org/2000/svg">
  <rect width="660" height="340" rx="22" fill="#f8fafc" />
  <text class="svg-label" x="34" y="24">How To Read The Collection</text>
  {''.join(rows)}
</svg>"""


def investigation_loop_svg() -> str:
    nodes = [
        (330, 46, "1. Identify", "Protocol + layer"),
        (552, 160, "2. Inspect", "Header fields"),
        (468, 286, "3. Compare", "Normal vs abnormal"),
        (192, 286, "4. Hunt", "Signals + pivots"),
        (108, 160, "5. Validate", "RFC behavior"),
    ]
    circles = []
    for x, y, title, subtitle in nodes:
        circles.append(f"""
  <circle cx="{x}" cy="{y}" r="62" fill="#dbeafe" stroke="#2563eb" stroke-width="3" />
  <text class="svg-label" x="{x}" y="{y - 5}" text-anchor="middle">{html.escape(title)}</text>
  <text class="svg-small" x="{x}" y="{y + 16}" text-anchor="middle">{html.escape(subtitle)}</text>""")
    return f"""<svg class="learning-svg" viewBox="0 0 660 360" role="img" aria-label="Threat hunting investigation loop" xmlns="http://www.w3.org/2000/svg">
  <rect width="660" height="360" rx="22" fill="#eff6ff" />
  <path d="M385 70 C500 72 590 118 588 178" fill="none" stroke="#64748b" stroke-width="4" marker-end="url(#arrow)" />
  <path d="M540 218 C490 318 370 336 282 306" fill="none" stroke="#64748b" stroke-width="4" marker-end="url(#arrow)" />
  <path d="M170 248 C90 210 76 116 258 66" fill="none" stroke="#64748b" stroke-width="4" marker-end="url(#arrow)" />
  <defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="#64748b" /></marker></defs>
  {''.join(circles)}
</svg>"""


def make_learning_guide(book: epub.EpubBook, builds: list[RFCBuild]) -> epub.EpubHtml:
    chapter = epub.EpubHtml(title="Learning Guide", file_name="learning-guide.xhtml", lang="en")
    chapter.content = f"""<h1>Learning Guide</h1>
<p>This EPUB is structured as a field guide: start with protocol role, inspect the fields that create observable traffic, then map abnormal behavior to hunting questions.</p>
{protocol_stack_svg()}
{category_chart_svg(builds)}
{investigation_loop_svg()}
<div class="checkpoint"><p class="kicker">Suggested path</p><ol>
<li>Read the seed RFCs first: UDP, IPv4, ICMP, TCP, ARP, DNS, DHCP, OSPF, BGP, SMTP, HTTP, IPFIX, IPsec, and ESP.</li>
<li>Use update-chain RFCs when modern behavior differs from the historical baseline.</li>
<li>For each chapter, turn the relevance note into a detection question and the header/reference panels into parsing checks.</li>
</ol></div>"""
    chapter.add_item(book.get_item_with_id("style_nav"))
    book.add_item(chapter)
    return chapter


def make_flashcard_appendix(book: epub.EpubBook, builds: list[RFCBuild], file_name: str = "study-cards.xhtml") -> epub.EpubHtml:
    cards = generate_flashcards(builds)
    chapter = epub.EpubHtml(title="Study Cards", file_name=file_name, lang="en")
    grouped: dict[str, list[dict[str, str]]] = {}
    for card in cards:
        grouped.setdefault(card["rfc"], []).append(card)
    sections = []
    for rfc_num in sorted(grouped, key=int):
        items = []
        for card in grouped[rfc_num][:8]:
            items.append(f"""<li class="checkpoint"><p><strong>{html.escape(card['category'])}:</strong> {html.escape(card['prompt'])}</p><p class="answer">{html.escape(card['answer']).replace(chr(10), '<br />')}</p></li>""")
        sections.append(f"<h2>RFC {html.escape(rfc_num)}</h2><ol>{''.join(items)}</ol>")
    chapter.content = f"""<h1>Study Cards</h1>
<p>Question-and-answer prompts for spaced review. Each answer is shown inline so this appendix works on any EPUB reader.</p>
{''.join(sections)}"""
    chapter.add_item(book.get_item_with_id("style_nav"))
    book.add_item(chapter)
    return chapter


def make_collection_index(book: epub.EpubBook, builds: list[RFCBuild], title: str, file_name: str = "collection-index.xhtml") -> epub.EpubHtml:
    chapter = epub.EpubHtml(title=title, file_name=file_name, lang="en")
    seed_count = sum(not build.meta.update_chain for build in builds)
    items = []
    for build in builds:
        meta = build.meta
        source = "update-chain" if meta.update_chain else "seed"
        items.append(
            f'<li><a href="{epub_chapter_file(meta.num)}">RFC {meta.num}: {html.escape(meta.title)}</a>'
            f'<br /><span class="muted">{html.escape(source)} · {html.escape(", ".join(meta.tags))}</span></li>'
        )
    chapter.content = f"""<h1>{html.escape(title)}</h1>
<p>{len(builds)} RFCs total: {seed_count} seed RFCs and {len(builds) - seed_count} update-chain context RFCs.</p>
<ul class="index-list">{''.join(items)}</ul>"""
    chapter.add_item(book.get_item_with_id("style_nav"))
    book.add_item(chapter)
    return chapter


def make_category_index(book: epub.EpubBook, builds: list[RFCBuild], tag: str) -> epub.EpubHtml:
    chapter = epub.EpubHtml(title=tag.title(), file_name=f"category-{tag}.xhtml", lang="en")
    tagged = [build for build in builds if tag in build.meta.tags]
    links = "".join(
        f'<li><a href="{epub_chapter_file(build.meta.num)}">RFC {build.meta.num}: {html.escape(build.meta.title)}</a></li>'
        for build in tagged
    )
    chapter.content = f"""<h1>{html.escape(tag.title())}</h1>
<div class="category-card"><p>{html.escape(TAG_DESCRIPTIONS[tag])}</p><p><strong>{len(tagged)} RFCs</strong> in this category.</p></div>
<ul class="index-list">{links}</ul>"""
    chapter.add_item(book.get_item_with_id("style_nav"))
    book.add_item(chapter)
    return chapter


def write_complete_epub(builds: list[RFCBuild]) -> None:
    book = make_book("RFC Threat Hunting Collection - Complete", "rfc-threat-hunting-complete")
    intro = make_intro(book, "RFC Threat Hunting Collection", "A complete single-volume protocol field library.")
    learning_guide = make_learning_guide(book, builds)
    collection_index = make_collection_index(book, builds, "RFC Index")
    chapters = []
    local_nums = {build.meta.num for build in builds}
    for build in builds:
        meta = build.meta
        chapter = epub.EpubHtml(title=f"RFC {meta.num}: {meta.title}", file_name=epub_chapter_file(meta.num), lang="en")
        chapter.content = chapter_content(build, local_nums, include_category=True)
        chapter.add_item(book.get_item_with_id("style_nav"))
        book.add_item(chapter)
        chapters.append(chapter)
    flashcards = make_flashcard_appendix(book, builds)
    book.toc = (intro, learning_guide, collection_index, (epub.Section("RFC Chapters"), tuple(chapters)), flashcards)
    book.spine = ["nav", intro, learning_guide, collection_index, *chapters, flashcards]
    book.add_item(epub.EpubNcx())
    book.add_item(epub.EpubNav())
    epub.write_epub(str(EPUB_DIR / "rfc-threat-hunting-complete.epub"), book)


def write_category_epub(builds: list[RFCBuild]) -> None:
    book = make_book("RFC Threat Hunting Collection - By Category", "rfc-threat-hunting-by-category")
    intro = make_intro(book, "RFC Threat Hunting By Category", "The same RFCs grouped by analyst workflow: application, monitoring, routing, security, and transport.")
    learning_guide = make_learning_guide(book, builds)
    spine: list[object] = ["nav", intro, learning_guide]
    toc: list[object] = [intro, learning_guide]
    local_nums = {build.meta.num for build in builds}
    chapter_by_num: dict[int, epub.EpubHtml] = {}
    for build in builds:
        meta = build.meta
        chapter = epub.EpubHtml(title=f"RFC {meta.num}: {meta.title}", file_name=epub_chapter_file(meta.num), lang="en")
        chapter.content = chapter_content(build, local_nums, include_category=True)
        chapter.add_item(book.get_item_with_id("style_nav"))
        book.add_item(chapter)
        chapter_by_num[meta.num] = chapter
    for tag in sorted(TAG_DESCRIPTIONS):
        category_intro = make_category_index(book, builds, tag)
        spine.append(category_intro)
        category_chapters = [chapter_by_num[build.meta.num] for build in builds if tag in build.meta.tags]
        toc.append((epub.Section(tag.title()), (category_intro, *category_chapters)))
    spine.extend(chapter_by_num[num] for num in sorted(chapter_by_num))
    flashcards = make_flashcard_appendix(book, builds)
    spine.append(flashcards)
    toc.append(flashcards)
    book.toc = tuple(toc)
    book.spine = spine
    book.add_item(epub.EpubNcx())
    book.add_item(epub.EpubNav())
    epub.write_epub(str(EPUB_DIR / "rfc-threat-hunting-by-category.epub"), book)


def build_epubs(builds: list[RFCBuild]) -> None:
    if EPUB_DIR.exists():
        shutil.rmtree(EPUB_DIR)
    EPUB_DIR.mkdir(parents=True)
    write_complete_epub(builds)
    write_category_epub(builds)


def print_summary(builds: Iterable[RFCBuild], added_count: int) -> None:
    print("\nBuild summary")
    print("=============")
    print(f"Additional RFCs pulled via update chain: {added_count}")
    for build in builds:
        meta = build.meta
        parts = []
        parts.append("txt: ok" if build.text_ok else f"txt: failed ({build.text_error})")
        parts.append("html: ok" if build.html_ok else f"html: failed ({build.html_error})")
        source = "update-chain" if meta.update_chain else "seed"
        print(f"RFC {meta.num:>4} [{source}] - {meta.title}: " + "; ".join(parts))
    print("\nOutputs")
    print(f"- Static site: {SITE_DIR}")
    print(f"- EPUB complete: {EPUB_DIR / 'rfc-threat-hunting-complete.epub'}")
    print(f"- EPUB by category: {EPUB_DIR / 'rfc-threat-hunting-by-category.epub'}")


def main() -> int:
    builds, added_count = expand_collection(max_depth=2)
    build_site(builds)
    build_epubs(builds)
    print_summary(builds, added_count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
