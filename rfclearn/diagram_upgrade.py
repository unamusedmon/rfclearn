"""Readable diagram rendering and post-processing for RFC Learn.

Known protocol figures are drawn explicitly. Unknown ASCII diagrams are kept
faithful in clean monospace panels. Labels and short fragments are never
promoted into fake diagram cards.
"""

from __future__ import annotations

import hashlib
import html
import re
import textwrap
from pathlib import Path
from typing import Any, Iterable

_DIAGRAM_CACHE: dict[str, str] = {}


from .config import SITE_DIR, HEADER_REFERENCES

ASCII_BLOCK_RE = re.compile(
    r"(?P<open><pre(?P<attrs>[^>]*)>)(?P<body>.*?)(?P<close></pre>)",
    flags=re.IGNORECASE | re.DOTALL,
)

DIAGRAM_PANEL_RE = re.compile(
    r'<figure class="rfc-diagram-panel" data-rfclearn-diagram="ascii-panel">\s*'
    r'<figcaption>(?P<caption>.*?)</figcaption>\s*'
    r'<div class="rfc-diagram-scroll">\s*<pre>(?P<body>.*?)</pre>\s*</div>\s*'
    r'</figure>',
    flags=re.IGNORECASE | re.DOTALL,
)

UPGRADED_MARKER = "data-rfclearn-diagram"
RFC_NUM_RE = re.compile(r"rfc(?P<num>\d+)\.html$", re.I)


def _strip_html(text: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", text))


def _looks_like_diagram(text: str) -> bool:
    clean = _strip_html(text).strip("\n")
    if not clean:
        return False
    lines = [line.rstrip("\n") for line in clean.splitlines() if line.strip()]

    # One-line labels like "Packet Reception:" are not diagrams. Neither are
    # tiny two-line fragments produced by old RFC page splitting.
    if len(lines) < 3 or len(clean) < 90:
        return False
    if all(line.strip().endswith(":") for line in lines):
        return False

    diagram_chars = sum(ch in "+-|_:/\\<>[]{}=*~^`" for ch in clean)
    longest_line = max(len(line) for line in lines)
    has_box = any(re.search(r"\+[-=]{3,}\+|\|.*\|", line) for line in lines)
    has_ruling = any(re.search(r"[-=+_]{5,}", line) for line in lines)
    has_arrows = any(token in line for line in lines for token in ("->", "<-", "-->", "<--", "=>", "<="))
    density = diagram_chars / max(len(clean), 1)

    return longest_line >= 24 and density >= 0.10 and (has_box or has_arrows or (has_ruling and len(lines) >= 4))


def _normalize_ascii(text: str) -> str:
    clean = _strip_html(text)
    clean = clean.replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    lines = [line.rstrip() for line in clean.splitlines()]
    return textwrap.dedent("\n".join(lines)).strip("\n")


def _rfc_num_from_path(path: Path | None) -> int | None:
    if not path:
        return None
    match = RFC_NUM_RE.search(path.name)
    return int(match.group("num")) if match else None


def render_ascii_diagram_panel(raw: str, *, title: str = "RFC diagram") -> str:
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
    """Render ASCII diagrams as SVG using the enhanced diagram renderer."""
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
    
    # Check the diagram cache first
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if h in _DIAGRAM_CACHE:
        mermaid_code = _DIAGRAM_CACHE[h]
        return f'<div class="mermaid">\n{mermaid_code}\n</div>'

    # Use the enhanced SVG renderer from diagram_renderer
    from . import diagram_renderer

    
    if not _looks_like_diagram(raw):
        return f'<pre class="rfc-readable-pre">{html.escape(_strip_html(raw))}</pre>'
    
    # Convert ASCII diagram to SVG
    lines = raw.split('\n')
    svg_output = diagram_renderer.render_modern_ascii_diagram_v2(lines, title)
    
    # If the renderer returned a fallback with ASCII, wrap it properly
    if '<pre' in svg_output and 'modern-diagram-fallback' in svg_output:
        return render_ascii_diagram_panel(raw, title=str(title))
    
    return svg_output


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


def render_header_layout_svg(header_ref: dict[str, Any]) -> str:
    """Render fields into 32-bit SVG rows with proportional blocks."""
    fields = header_ref.get("fields", [])
    title = str(header_ref.get("title", "Protocol header"))
    note = str(header_ref.get("note", ""))

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
    
    svg_markup = (
        f'<svg class="header-bit-layout" viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="0-31 bit layout diagram" xmlns="http://www.w3.org/2000/svg">'
        f'<desc>0-31 bit positions across each row; fields are drawn as blocks spanning their bit widths.</desc>'
        f'{top_labels}{grid_lines}{"".join(blocks)}</svg>'
    )

    return (
        '<figure class="rfc-header-panel" data-rfclearn-diagram="header-panel">'
        '<div class="header-panel-title">'
        f'<h3>{html.escape(title)}</h3>'
        + (f'<p>{html.escape(note)}</p>' if note else '')
        + '</div>'
        '<div class="rfc-header-svg-container">'
        + svg_markup
        + '</div>'
        '</figure>'
    )



def flow_figure(title: str, steps: list[tuple[str, str]], *, ident: str) -> str:
    cards = "".join(
        '<article class="flow-step">'
        f'<strong>{html.escape(label)}</strong>'
        f'<p>{html.escape(text)}</p>'
        '</article>'
        for label, text in steps
    )
    return (
        f'<figure class="rfc-flow-figure" data-rfclearn-diagram="{html.escape(ident)}">'
        f'<figcaption>{html.escape(title)}</figcaption>'
        '<div class="flow-track">'
        + cards +
        '</div>'
        '</figure>'
    )


KNOWN_FLOW_FIGURES: dict[int, list[tuple[str, list[tuple[str, str]], str]]] = {
    768: [
        ("UDP datagram handling", [
            ("Application data", "A process writes a message to a UDP socket."),
            ("UDP header", "Source port, destination port, length, and checksum are added."),
            ("IP delivery", "The datagram is handed to IP without connection setup or retransmission state."),
            ("Receiver", "The destination host demultiplexes by destination port and checksum result."),
        ], "udp-datagram-flow"),
    ],
    791: [
        ("IPv4 forwarding and delivery", [
            ("Application", "A local program submits data for delivery."),
            ("Internet module", "IPv4 chooses addresses, fills header fields, and fragments when needed."),
            ("Local network", "The packet is carried inside a local-network frame."),
            ("Gateway", "Routers decrement TTL and forward toward the destination network."),
            ("Destination", "The receiver validates, reassembles fragments, and delivers the payload upward."),
        ], "ipv4-forwarding-flow"),
        ("Packet reception path", [
            ("Frame arrives", "The network interface receives a frame containing an IPv4 datagram."),
            ("Validate header", "The internet module checks destination, length, checksum, TTL, and protocol."),
            ("Reassemble", "Fragments are buffered until a complete datagram is available or timeout occurs."),
            ("Demultiplex", "The Protocol field selects TCP, UDP, ICMP, or another upper-layer handler."),
            ("Deliver metadata", "Payload, source address, and related parameters are returned to the application path."),
        ], "ipv4-reception-flow"),
    ],
    792: [
        ("ICMP error-message path", [
            ("Problem observed", "A router or host cannot deliver or process an IP datagram."),
            ("ICMP generated", "Type and Code describe the failure class and reason."),
            ("Original packet quoted", "The ICMP body includes the original IP header and enough data for correlation."),
            ("Source notified", "The sender uses the error for diagnostics, path discovery, or connection feedback."),
        ], "icmp-error-flow"),
    ],
    793: [
        ("TCP connection lifecycle", [
            ("SYN", "The client proposes a connection and initial sequence number."),
            ("SYN-ACK", "The server acknowledges and returns its own sequence number."),
            ("ACK", "The client completes the handshake; data can now flow."),
            ("Data transfer", "Sequence and acknowledgment numbers track reliable byte streams."),
            ("FIN/RST", "Connections close gracefully with FIN or abruptly with RST."),
        ], "tcp-lifecycle-flow"),
    ],
    826: [
        ("ARP address resolution", [
            ("Need MAC", "A host knows the target IP but not the Ethernet address."),
            ("Broadcast request", "Who has this protocol address? Tell the sender."),
            ("Unicast reply", "The owner responds with its hardware address."),
            ("Cache mapping", "The sender stores IP-to-MAC mapping for later frames."),
            ("Hunting angle", "Unexpected replies or gateway remaps are poisoning signals."),
        ], "arp-resolution-flow"),
    ],
    1035: [
        ("DNS query and response", [
            ("Question", "A resolver asks for a name, type, and class."),
            ("Recursion/delegation", "The resolver follows authority data or asks an upstream server."),
            ("Answer", "Resource records return data, TTLs, and response code state."),
            ("Cache", "The resolver stores positive or negative results according to TTL and policy."),
        ], "dns-resolution-flow"),
    ],
    2131: [
        ("DHCP DORA exchange", [
            ("Discover", "Client broadcasts to find available DHCP servers."),
            ("Offer", "Server proposes an address and configuration options."),
            ("Request", "Client requests one offered lease."),
            ("Ack", "Server commits the lease and sends final parameters."),
            ("Watch", "Rogue offers, unexpected relays, and duplicate leases are high-signal."),
        ], "dhcp-dora-flow"),
    ],
    2328: [
        ("OSPF adjacency and flooding", [
            ("Hello", "Neighbors discover each other on a link."),
            ("Database sync", "Routers exchange summaries and request missing LSAs."),
            ("LSA flood", "Topology changes propagate through the area."),
            ("SPF", "Each router computes best paths from the link-state database."),
        ], "ospf-adjacency-flow"),
    ],
    2460: [
        ("IPv6 next-header chain", [
            ("Fixed header", "IPv6 carries base delivery fields and a Next Header pointer."),
            ("Extension headers", "Hop-by-hop, routing, fragment, destination, or security headers may follow."),
            ("Upper layer", "The final Next Header selects TCP, UDP, ICMPv6, ESP, or another protocol."),
            ("Hunting angle", "Long, rare, or malformed chains can expose evasion and parser gaps."),
        ], "ipv6-extension-flow"),
    ],
    3954: [
        ("NetFlow v9 export model", [
            ("Exporter", "Network device observes flows and maintains counters."),
            ("Template", "Field layout is sent so collectors can decode later records."),
            ("Data records", "Observed flow values are exported according to the template."),
            ("Collector", "Sequence gaps, exporter resets, and template churn affect evidence quality."),
        ], "netflow-export-flow"),
    ],
    4271: [
        ("BGP route advertisement", [
            ("NLRI", "A prefix is advertised or withdrawn."),
            ("Path attributes", "AS_PATH, NEXT_HOP, ORIGIN, and policy attributes describe reachability."),
            ("Decision process", "Routers select best paths and apply local policy."),
            ("Propagation", "Accepted routes are advertised to eligible peers."),
            ("Hunting angle", "Impossible AS paths, odd next hops, and sudden origin changes indicate trouble."),
        ], "bgp-update-flow"),
    ],
    4301: [
        ("IPsec policy path", [
            ("Selector match", "Traffic is matched against IPsec policy selectors."),
            ("Security association", "A matching SA determines protection behavior."),
            ("Protect/bypass/discard", "Traffic is encrypted, allowed in cleartext, or dropped."),
            ("Audit", "Policy mismatches explain unexpected tunnel or cleartext behavior."),
        ], "ipsec-policy-flow"),
    ],
    4303: [
        ("ESP packet protection", [
            ("SPI lookup", "The receiver uses SPI to identify the security association."),
            ("Sequence check", "Anti-replay state validates packet order and freshness."),
            ("Decrypt/authenticate", "Payload protection is verified according to negotiated algorithms."),
            ("Next Header", "The recovered inner protocol is delivered if checks pass."),
        ], "esp-protection-flow"),
    ],
    5321: [
        ("SMTP transaction", [
            ("Connect", "Client opens a TCP session to the mail server."),
            ("EHLO/HELO", "Client identifies itself and discovers extensions."),
            ("MAIL/RCPT", "Envelope sender and recipients are declared."),
            ("DATA", "Message content is transferred."),
            ("Queue/relay", "Server accepts, rejects, queues, or relays the message."),
        ], "smtp-transaction-flow"),
    ],
    7011: [
        ("IPFIX export model", [
            ("Observation point", "Traffic is observed at an interface, device, or domain."),
            ("Metering process", "Packets are aggregated into flow records."),
            ("Template sets", "Record schemas are exported to collectors."),
            ("Data sets", "Flow values are sent with sequence and domain identifiers."),
            ("Collector", "Records become normalized telemetry for hunting."),
        ], "ipfix-export-flow"),
    ],
    7540: [
        ("HTTP/2 framing model", [
            ("Connection", "A single TCP/TLS connection carries many streams."),
            ("Frames", "Binary frames carry headers, data, settings, priority, and control state."),
            ("Streams", "Independent request/response exchanges are multiplexed by stream ID."),
            ("Flow control", "Window state governs how much data can be sent."),
            ("Hunting angle", "Odd frame sequences, stream abuse, or compression anomalies can expose attacks."),
        ], "http2-framing-flow"),
    ],
}


def cleanup_bad_diagram_panels(document: str) -> str:
    """Undo fake diagram cards created by earlier/broader heuristics."""
    def replace(match: re.Match[str]) -> str:
        raw = html.unescape(match.group("body"))
        normalized = _normalize_ascii(raw)
        if _looks_like_diagram(normalized):
            return match.group(0)
        if not normalized:
            return ""
        if len(normalized) <= 120 and "\n" not in normalized:
            return f'<p class="figure-label">{html.escape(normalized)}</p>'
        return f'<pre class="rfc-readable-pre">{html.escape(normalized)}</pre>'
    return DIAGRAM_PANEL_RE.sub(replace, document)


def inject_known_header(document: str, rfc_num: int | None) -> str:
    if not rfc_num or rfc_num not in HEADER_REFERENCES:
        return document
    marker = 'data-rfclearn-diagram="header-panel"'
    title = str(HEADER_REFERENCES[rfc_num].get("title", ""))
    if marker in document and title and title in document:
        return document
    panel = render_header_layout_svg(HEADER_REFERENCES[rfc_num])
    if not panel:
        return document
    insert_after = re.search(r"</header>|</section>", document, flags=re.I)
    if insert_after:
        return document[:insert_after.end()] + panel + document[insert_after.end():]
    body_match = re.search(r"<body[^>]*>", document, flags=re.I)
    if body_match:
        return document[:body_match.end()] + panel + document[body_match.end():]
    return panel + document


def inject_known_flows(document: str, rfc_num: int | None) -> str:
    if not rfc_num or rfc_num not in KNOWN_FLOW_FIGURES:
        return document
    figures = []
    for title, steps, ident in KNOWN_FLOW_FIGURES[rfc_num]:
        marker = f'data-rfclearn-diagram="{html.escape(ident)}"'
        if marker not in document:
            figures.append(flow_figure(title, steps, ident=ident))
    if not figures:
        return document
    payload = '<section class="protocol-figure-deck" aria-label="Protocol visual summaries">' + "".join(figures) + '</section>'
    header_panel = re.search(r"</figure>", document, flags=re.I)
    if header_panel and 'data-rfclearn-diagram="header-panel"' in document[:header_panel.end()]:
        return document[:header_panel.end()] + payload + document[header_panel.end():]
    insert_after = re.search(r"</header>|</section>", document, flags=re.I)
    if insert_after:
        return document[:insert_after.end()] + payload + document[insert_after.end():]
    return payload + document


def upgrade_html_diagrams(document: str) -> str:
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
        rfc_num = _rfc_num_from_path(path)
        upgraded = ensure_css_link(original)
        upgraded = cleanup_bad_diagram_panels(upgraded)
        upgraded = upgrade_html_diagrams(upgraded)
        upgraded = cleanup_bad_diagram_panels(upgraded)
        upgraded = inject_known_header(upgraded, rfc_num)
        upgraded = inject_known_flows(upgraded, rfc_num)
        if upgraded != original:
            path.write_text(upgraded, encoding="utf-8")
            changed += 1
    return changed


def install_diagram_upgrade(builder_module: Any) -> None:
    global _DIAGRAM_CACHE
    _DIAGRAM_CACHE = getattr(builder_module, "DIAGRAM_CACHE", {})
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
.rfc-diagram-panel,
.rfc-flow-figure {
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

.protocol-figure-deck {
  max-width: min(1120px, 100%);
  margin: 1rem auto 1.65rem;
}

.header-panel-title,
.rfc-diagram-panel figcaption,
.rfc-flow-figure figcaption {
  padding: 1rem 1.15rem .85rem;
  border-bottom: 1px solid rgba(255,255,255,.09);
}

.header-panel-title h3,
.rfc-diagram-panel figcaption,
.rfc-flow-figure figcaption {
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
.packet-field.small { min-width: 8.5rem; }
.packet-field.huge { flex-basis: min(100%, 24rem); }

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

.flow-track {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
  gap: .75rem;
  padding: 1rem;
}

.flow-step {
  position: relative;
  min-height: 8.25rem;
  padding: .95rem;
  border: 1px solid rgba(255,255,255,.10);
  border-radius: 1rem;
  background: linear-gradient(145deg, rgba(101,228,255,.07), rgba(184,156,255,.045));
}

.flow-step:not(:last-child)::after {
  content: "→";
  position: absolute;
  right: -.72rem;
  top: 50%;
  transform: translateY(-50%);
  width: 1.45rem;
  height: 1.45rem;
  display: grid;
  place-items: center;
  border-radius: 50%;
  color: #07101d;
  background: var(--cyan, #65e4ff);
  font-weight: 950;
  z-index: 1;
}

.flow-step strong {
  display: block;
  color: #eef7ff;
  font-size: .98rem;
  line-height: 1.25;
}

.flow-step p {
  margin: .48rem 0 0;
  color: var(--muted, #9fb0c9);
  font-size: .84rem;
  line-height: 1.45;
}

.rfc-diagram-scroll { overflow-x: auto; padding: 1rem; }

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

.figure-label {
  max-width: 82ch;
  margin: 1rem auto;
  color: var(--cyan, #65e4ff);
  font-weight: 850;
}

.rfc-diagram-source {
  margin: .75rem 1rem 1rem;
  color: var(--muted, #9fb0c9);
  font-size: .9rem;
}

.rfc-diagram-source summary { cursor: pointer; user-select: none; }
.rfc-diagram-source pre { overflow-x: auto; padding: .8rem; border-radius: .75rem; background: rgba(255,255,255,.055); }

@media (max-width: 720px) {
  .packet-field-grid,
  .flow-track { display: grid; grid-template-columns: 1fr; }
  .packet-field { min-width: 0; }
  .flow-step:not(:last-child)::after { display: none; }
  .rfc-diagram-panel pre { font-size: .86rem; }
}
"""
