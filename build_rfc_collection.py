#!/usr/bin/env python3
"""Build a local RFC threat-hunting reference site and EPUB collection."""

from __future__ import annotations

import html
import re
import shutil
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    from ebooklib import epub
except ImportError as exc:  # pragma: no cover - user-facing setup guard
    raise SystemExit(
        "ebooklib is required. Install dependencies with: python3 -m pip install -r requirements.txt"
    ) from exc


ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
SITE_DIR = ROOT / "site"
EPUB_DIR = ROOT / "epub"
RFC_BASE = "https://www.rfc-editor.org/rfc/rfc{num}.{ext}"


@dataclass(frozen=True)
class RFCMeta:
    num: int
    title: str
    relevance: str
    tags: tuple[str, ...]
    keywords: tuple[str, ...] = ()
    update_chain: bool = False


@dataclass
class RFCBuild:
    meta: RFCMeta
    text_path: Path | None = None
    html_path: Path | None = None
    text_ok: bool = False
    html_ok: bool = False
    text_error: str | None = None
    html_error: str | None = None
    depth: int = 0


RFCS: tuple[RFCMeta, ...] = (
    RFCMeta(768, "User Datagram Protocol", "Defines UDP, the lightweight transport behind DNS, telemetry, scanning, and many amplification patterns.", ("transport",), ("udp", "datagram", "port")),
    RFCMeta(791, "Internet Protocol", "Establishes IPv4 fields that hunters inspect for fragmentation, spoofing, tunneling, and routing anomalies.", ("routing", "security"), ("ipv4", "fragment", "ttl")),
    RFCMeta(792, "Internet Control Message Protocol", "Documents ICMP behavior used in reconnaissance, diagnostics, covert channels, and denial-of-service activity.", ("routing", "security"), ("icmp", "ping", "error")),
    RFCMeta(793, "Transmission Control Protocol", "Defines TCP state, flags, sequencing, and connection semantics central to flow analysis and intrusion detection.", ("transport",), ("tcp", "syn", "ack", "reset")),
    RFCMeta(826, "An Ethernet Address Resolution Protocol", "Explains ARP resolution, a core source of local-network spoofing, poisoning, and lateral movement signals.", ("routing", "security"), ("arp", "ethernet", "mac")),
    RFCMeta(1035, "Domain Names - Implementation and Specification", "Defines DNS messages and resource records that drive domain hunting, tunneling detection, and infrastructure analysis.", ("application", "monitoring"), ("dns", "query", "record")),
    RFCMeta(1122, "Requirements for Internet Hosts - Communication Layers", "Clarifies host-layer protocol requirements useful when spotting malformed stacks and evasive implementations.", ("transport", "routing", "security"), ("host", "tcp", "ip")),
    RFCMeta(1123, "Requirements for Internet Hosts - Application and Support", "Covers host application requirements that help contextualize DNS, SMTP, and service behavior in investigations.", ("application",), ("host", "dns", "smtp")),
    RFCMeta(2131, "Dynamic Host Configuration Protocol", "Defines DHCP exchanges used to investigate rogue servers, device identity, and network access patterns.", ("application", "monitoring"), ("dhcp", "lease", "client")),
    RFCMeta(2460, "Internet Protocol, Version 6 (IPv6) Specification", "Defines IPv6 headers and extension behavior relevant to modern routing, filtering, and evasion analysis.", ("routing", "security"), ("ipv6", "extension", "fragment")),
    RFCMeta(2616, "Hypertext Transfer Protocol -- HTTP/1.1", "Historical HTTP/1.1 baseline for understanding legacy web traffic, proxy behavior, and suspicious request patterns.", ("application", "monitoring"), ("http", "proxy", "header")),
    RFCMeta(2782, "A DNS RR for specifying the location of services (DNS SRV)", "Defines SRV records often used to discover services, domain infrastructure, and enterprise authentication targets.", ("application", "monitoring"), ("dns", "srv", "service")),
    RFCMeta(2328, "OSPF Version 2", "Documents OSPF routing behavior important for detecting route manipulation and internal network reconnaissance.", ("routing",), ("ospf", "route", "link-state")),
    RFCMeta(3954, "Cisco Systems NetFlow Services Export Version 9", "Defines NetFlow v9 export data, a major telemetry source for network threat hunting.", ("monitoring",), ("netflow", "telemetry", "flow")),
    RFCMeta(4271, "A Border Gateway Protocol 4 (BGP-4)", "Defines BGP behavior behind route leaks, hijacks, suspicious peering, and internet-scale traffic shifts.", ("routing", "security"), ("bgp", "as", "prefix")),
    RFCMeta(4301, "Security Architecture for the Internet Protocol", "Describes IPsec architecture for identifying expected encrypted tunnels and policy anomalies.", ("security",), ("ipsec", "security association", "policy")),
    RFCMeta(4303, "IP Encapsulating Security Payload (ESP)", "Defines ESP packet protection, useful for recognizing IPsec traffic and tunnel encapsulation artifacts.", ("security", "transport"), ("esp", "ipsec", "encryption")),
    RFCMeta(5321, "Simple Mail Transfer Protocol", "Defines SMTP behavior used in phishing infrastructure analysis, mail relay abuse, and command-level investigations.", ("application", "monitoring"), ("smtp", "mail", "relay")),
    RFCMeta(7011, "Specification of the IP Flow Information Export (IPFIX) Protocol", "Defines IPFIX, the standards-based flow telemetry protocol used for large-scale hunting and detection.", ("monitoring",), ("ipfix", "flow", "telemetry")),
    RFCMeta(7230, "Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing", "Modernizes HTTP/1.1 message parsing and routing rules relevant to web attack and proxy investigations.", ("application", "monitoring"), ("http", "header", "routing")),
    RFCMeta(7540, "Hypertext Transfer Protocol Version 2 (HTTP/2)", "Defines HTTP/2 framing and streams used to analyze modern web traffic, proxies, and protocol abuse.", ("application", "transport"), ("http2", "h2", "frame")),
)


TAG_DESCRIPTIONS = {
    "transport": "Transport semantics, ports, flags, sessions, framing, and encapsulation.",
    "application": "Application-layer behavior, service discovery, mail, web, and naming protocols.",
    "routing": "Addressing, forwarding, route exchange, path selection, and local resolution.",
    "monitoring": "Telemetry sources and high-signal data structures used during hunting.",
    "security": "Security architecture, abuse primitives, evasions, and protocol risks.",
    "update-chain": "RFCs pulled in because they update, obsolete, or are obsoleted by the seed collection.",
}


HEADER_REFERENCES: dict[int, dict[str, object]] = {
    768: {
        "title": "RFC 768 UDP Header",
        "note": "UDP is compact and often abused for reflection, tunneling, and scanning because there is no session state in the header.",
        "fields": [
            ("Source Port", 16, "Originating service or ephemeral port; zero, unusual, or impossible pairings can signal spoofing or crafted traffic."),
            ("Destination Port", 16, "Target service port; watch for amplification services, unexpected high-value services, and scan fan-out."),
            ("Length", 16, "UDP header plus payload length; mismatches or tiny/oversized lengths indicate malformed packets or evasion."),
            ("Checksum", 16, "Integrity check over pseudo-header and payload; zero in IPv4 or invalid values can reveal crafted packets."),
        ],
    },
    791: {
        "title": "RFC 791 IPv4 Header",
        "note": "IPv4 header fields expose spoofing, fragmentation, routing, and TTL anomalies before payload parsing starts.",
        "fields": [
            ("Version", 4, "Should be 4 for IPv4; any other value indicates misclassification or malformed traffic."),
            ("IHL", 4, "Header length; unusually large values imply IP options, while invalid short values are malformed."),
            ("Type of Service", 8, "QoS/precedence byte; odd markings can indicate tunneling, policy abuse, or legacy stack artifacts."),
            ("Total Length", 16, "Full packet length; mismatches with capture length can indicate truncation, evasion, or malformed packets."),
            ("Identification", 16, "Fragment correlation value; predictable or repeated IDs help fingerprint hosts and spot fragmentation abuse."),
            ("Flags", 3, "DF/MF fragmentation controls; watch illegal reserved-bit use and suspicious fragmentation patterns."),
            ("Fragment Offset", 13, "Fragment position; tiny, overlapping, or excessive fragments are classic IDS evasion signals."),
            ("TTL", 8, "Decrements each hop; unusually low or inconsistent TTL can indicate spoofing or traceroute probing."),
            ("Protocol", 8, "Next-layer protocol number; unexpected values may indicate tunneling, scanning, or parser confusion."),
            ("Header Checksum", 16, "IPv4 header integrity; invalid values suggest corruption, offload artifacts, or crafted packets."),
            ("Source Address", 32, "Origin IPv4 address; private, bogon, or impossible sources on external links suggest spoofing."),
            ("Destination Address", 32, "Target IPv4 address; unexpected internal, multicast, or broadcast destinations deserve review."),
            ("Options/Padding", 32, "Optional and variable; rare on normal traffic, so source route/record route options are high-signal."),
        ],
    },
    793: {
        "title": "RFC 793 TCP Header",
        "note": "TCP fields drive flow reconstruction, scan detection, injection analysis, and session-state validation.",
        "fields": [
            ("Source Port", 16, "Client or service port; suspicious reuse, impossible services, or odd pairings can reveal scans or spoofing."),
            ("Destination Port", 16, "Target service port; hunt for unauthorized services, fan-out scans, or policy bypass attempts."),
            ("Sequence Number", 32, "Byte-stream position; repeated, predictable, or out-of-window values may indicate injection or spoofing."),
            ("Acknowledgment Number", 32, "Next expected byte when ACK is set; impossible ACKs reveal scans, desync, or spoofed packets."),
            ("Data Offset", 4, "TCP header length; large values mean options, while invalid small values are malformed."),
            ("Reserved", 6, "Should be zero in RFC 793; non-zero reserved bits often indicate crafted or evasive traffic."),
            ("TCP Flags", 6, "SYN/ACK/RST/FIN combinations; watch for illegal flag combos, SYN floods, or RST injection."),
            ("Window", 16, "Advertised receive window; zero-window abuse, odd scaling, or fingerprintable values can stand out."),
            ("Checksum", 16, "TCP integrity check; invalid values can be offload artifacts or crafted packet evidence."),
            ("Urgent Pointer", 16, "Only meaningful with URG; unexpected use is rare and can indicate evasion or legacy attacks."),
            ("Options/Padding", 32, "Variable options such as MSS, SACK, timestamps; odd combinations can fingerprint tools or evasions."),
        ],
    },
    1035: {
        "title": "RFC 1035 DNS Message Header",
        "note": "DNS header bits summarize query intent, recursion behavior, response state, and section counts used in tunneling and abuse hunts.",
        "fields": [
            ("ID", 16, "Transaction identifier; repeated, predictable, or mismatched IDs can indicate spoofing or cache-poisoning attempts."),
            ("QR", 1, "Query/response bit; responses without queries or queries marked as responses are suspicious."),
            ("Opcode", 4, "Operation code; non-standard opcodes are rare and high-signal."),
            ("AA", 1, "Authoritative answer; unexpected authority can indicate spoofing or rogue infrastructure."),
            ("TC", 1, "Truncation flag; frequent truncation can force TCP fallback or indicate oversized abuse."),
            ("RD", 1, "Recursion desired; unexpected recursion from restricted networks can show resolver misuse."),
            ("RA", 1, "Recursion available; rogue or exposed recursive resolvers often reveal themselves here."),
            ("Z", 3, "Reserved bits; non-zero values are abnormal except negotiated extensions."),
            ("RCODE", 4, "Response code; spikes in NXDOMAIN, SERVFAIL, or REFUSED can reveal DGA, outages, or probing."),
            ("QDCOUNT", 16, "Question count; values other than one are uncommon and may be malformed or evasive."),
            ("ANCOUNT", 16, "Answer count; unusual cardinality can indicate amplification, fast-flux, or malformed responses."),
            ("NSCOUNT", 16, "Authority count; unexpected delegations or large counts can expose suspicious DNS infrastructure."),
            ("ARCOUNT", 16, "Additional count; EDNS, glue, and oversized additional data are useful abuse indicators."),
        ],
    },
    2131: {
        "title": "RFC 2131 DHCP Message Header",
        "note": "DHCP fields identify clients, servers, leases, and relay paths during rogue-DHCP and device-identity investigations.",
        "fields": [
            ("op", 8, "Message op code; BOOTREQUEST/BOOTREPLY direction mismatches can reveal spoofing or relay issues."),
            ("htype", 8, "Hardware type; unexpected values on Ethernet networks can indicate crafted clients."),
            ("hlen", 8, "Hardware address length; invalid lengths break client identity and indicate malformed traffic."),
            ("hops", 8, "Relay hop count; high or unexpected values suggest relay loops or unusual topology."),
            ("xid", 32, "Transaction ID; collisions, repeats, or mismatches help spot spoofed offers and rogue servers."),
            ("secs", 16, "Elapsed seconds; high values can signal client distress or lease acquisition problems."),
            ("flags", 16, "Broadcast flag and reserved bits; abnormal reserved use may indicate crafted clients."),
            ("ciaddr", 32, "Client IP address; unexpected preconfigured values can reveal conflicts or spoofing."),
            ("yiaddr", 32, "Your/client IP address offered by server; watch unauthorized ranges or duplicate offers."),
            ("siaddr", 32, "Next server address; unexpected boot servers can indicate rogue provisioning."),
            ("giaddr", 32, "Relay agent address; unexpected relays may show rogue infrastructure or segmentation errors."),
            ("chaddr", 128, "Client hardware address; mismatches with L2 source indicate spoofing or relay oddities."),
            ("Magic Cookie", 32, "DHCP option marker; missing or wrong value indicates non-DHCP BOOTP or malformed packets."),
            ("Options", 32, "Variable options; hunt rogue DNS/router options, odd vendor classes, and lease manipulation."),
        ],
    },
    2328: {
        "title": "RFC 2328 OSPFv2 Packet Header",
        "note": "OSPF headers reveal adjacency abuse, area mismatches, authentication failures, and unexpected routing speakers.",
        "fields": [
            ("Version", 8, "Should be 2 for OSPFv2; mismatches indicate malformed or wrong-protocol traffic."),
            ("Type", 8, "Hello, DB Description, LS Request, LS Update, or LS Ack; unusual type bursts can show adjacency attacks."),
            ("Packet Length", 16, "Full OSPF packet length; mismatches suggest malformed packets or capture corruption."),
            ("Router ID", 32, "Originating router identity; duplicate or unexpected IDs indicate spoofing or misconfiguration."),
            ("Area ID", 32, "OSPF area; wrong-area packets are high-signal for rogue routers or topology leaks."),
            ("Checksum", 16, "OSPF packet integrity; invalid checksums indicate corruption or crafted traffic."),
            ("AuType", 16, "Authentication type; none or unexpected auth mode can expose insecure adjacencies."),
            ("Authentication", 64, "Authentication data; failures or mismatches can reveal adjacency hijack attempts."),
        ],
    },
    2460: {
        "title": "RFC 2460 IPv6 Header",
        "note": "IPv6 fixed headers plus extension chains expose tunneling, routing, fragmentation, and evasion patterns.",
        "fields": [
            ("Version", 4, "Should be 6 for IPv6; other values indicate malformed traffic or parser confusion."),
            ("Traffic Class", 8, "QoS markings; unusual values can indicate tunneling, covert marking, or policy abuse."),
            ("Flow Label", 20, "Flow identifier; unexpected non-zero or inconsistent labels can fingerprint hosts or tools."),
            ("Payload Length", 16, "Length after fixed header; zero jumbo payloads or mismatches deserve scrutiny."),
            ("Next Header", 8, "Upper-layer or extension header; long or unusual chains can bypass filters or hide payloads."),
            ("Hop Limit", 8, "IPv6 TTL equivalent; unusually low or inconsistent values suggest spoofing or probing."),
            ("Source Address", 128, "Origin IPv6 address; link-local, ULA, multicast, or spoofed sources in wrong zones are suspicious."),
            ("Destination Address", 128, "Target IPv6 address; unexpected multicast, link-local, or routed destinations aid hunting."),
        ],
    },
    4271: {
        "title": "RFC 4271 BGP Message Header",
        "note": "BGP message framing and UPDATE attributes are central to route-leak, hijack, and suspicious peering investigations.",
        "fields": [
            ("Marker", 128, "All ones unless authentication is used; wrong marker values indicate malformed or non-BGP traffic."),
            ("Length", 16, "Total BGP message length; abnormal sizes can indicate malformed messages or UPDATE floods."),
            ("Type", 8, "OPEN, UPDATE, NOTIFICATION, or KEEPALIVE; unexpected type sequences reveal session abuse or resets."),
            ("UPDATE Withdrawn Routes Length", 16, "Withdrawn prefix block size; spikes can reveal route leaks, flaps, or attacks."),
            ("Withdrawn Routes", 32, "Variable list of withdrawn prefixes; unexpected critical-prefix withdrawal is high-signal."),
            ("Path Attributes Length", 16, "Size of path attributes; malformed values can trigger parser bugs or session resets."),
            ("Path Attributes", 32, "AS_PATH manipulation is the primary vector for route hijacking; watch origin, next-hop, and community anomalies."),
            ("NLRI", 32, "Advertised prefixes; more-specific or unauthorized announcements indicate leaks or hijacks."),
        ],
    },
    5321: {
        "title": "RFC 5321 SMTP Command/Reply Fields",
        "note": "SMTP is line-oriented rather than a fixed binary header; this panel maps the primary command/reply fields analysts hunt in mail logs.",
        "fields": [
            ("Command Verb", 32, "HELO/EHLO, MAIL, RCPT, DATA, AUTH, STARTTLS; odd ordering or unsupported verbs indicate probing or abuse."),
            ("Reply Code", 24, "Three-digit server response; 5xx/4xx spikes can show credential attacks, relay probing, or delivery failures."),
            ("Enhanced Status", 32, "Optional x.y.z status; abnormal failures help separate policy blocks, auth problems, and reputation issues."),
            ("Mailbox Path", 32, "MAIL FROM/RCPT TO identity; null senders, lookalikes, and relay targets are hunting pivots."),
            ("Extension Args", 32, "ESMTP parameters such as SIZE, AUTH, STARTTLS; downgrades or suspicious auth use deserve review."),
        ],
    },
}

THREAT_INDICATORS: dict[int, list[dict[str, str]]] = {
    768: [
        {"name": "Amplification Attacks", "normal": "Payload size roughly matches query size.", "malicious": "Small query triggers massive response (e.g. DNS/NTP reflection).", "sev": "high"},
        {"name": "Port 0 Usage", "normal": "Ports range from 1-65535.", "malicious": "Source or destination port is 0, often used in fingerprinting or bypass.", "sev": "medium"},
        {"name": "Unusual Length Values", "normal": "Length field matches actual payload size.", "malicious": "Length field is larger than packet or impossibly small.", "sev": "high"},
    ],
    791: [
        {"name": "TTL Anomalies", "normal": "Consistent TTL values from a single host.", "malicious": "Abrupt TTL changes suggest spoofing or traceroute probing.", "sev": "medium"},
        {"name": "Fragmentation Abuse", "normal": "Standard fragmentation for large MTUs.", "malicious": "Overlapping or tiny fragments designed to bypass IDS/firewalls.", "sev": "high"},
        {"name": "Reserved Bit Set", "normal": "Reserved bit is always 0.", "malicious": "Evil bit (RFC 3514) or non-zero reserved bits in crafted traffic.", "sev": "low"},
        {"name": "Source Routing Options", "normal": "IP options are rare; routing is hop-by-hop.", "malicious": "Strict or loose source routing to bypass topology constraints.", "sev": "high"},
    ],
    793: [
        {"name": "Illegal Flag Combinions", "normal": "Valid state transitions (SYN, SYN-ACK, etc).", "malicious": "NULL, Xmas, or SYN-FIN scans; flags that shouldn't exist together.", "sev": "high"},
        {"name": "SYN Flood Patterns", "normal": "Balanced SYN and ACK packets.", "malicious": "Massive burst of SYNs without corresponding ACKs from many IPs.", "sev": "high"},
        {"name": "RST Injection", "normal": "RST sent on connection close or error.", "malicious": "Unsolicited RSTs designed to kill active legitimate sessions.", "sev": "medium"},
        {"name": "Window Size Anomalies", "normal": "Dynamic window scaling based on congestion.", "malicious": "Stuck at tiny values or zero-window probes to hang servers.", "sev": "medium"},
        {"name": "Urgent Pointer Abuse", "normal": "Rarely used in modern protocols.", "malicious": "Non-zero urgent pointer in data-less packets to trigger parser bugs.", "sev": "low"},
    ],
    1035: [
        {"name": "Long Subdomain Chains", "normal": "2-3 levels of subdomains (e.g. mail.google.com).", "malicious": "Many layers of encoded data in subdomains (DNS tunneling).", "sev": "high"},
        {"name": "High Entropy Labels", "normal": "Human-readable or dictionary-based names.", "malicious": "Random-looking strings (DGA or encoded exfiltration).", "sev": "high"},
        {"name": "TXT Record Abuse", "normal": "Brief descriptive text or SPF records.", "malicious": "Large payloads or encoded scripts stored in TXT records.", "sev": "medium"},
        {"name": "Zone Transfer Attempts", "normal": "AXFR restricted to authorized secondaries.", "malicious": "Unsolicited AXFR requests to map internal network domains.", "sev": "medium"},
        {"name": "Fast Flux Patterns", "normal": "IPs change occasionally for load balancing.", "malicious": "IPs change every few seconds to hide malicious infrastructure.", "sev": "high"},
    ],
    2131: [
        {"name": "Rogue Server Indicators", "normal": "DHCP offers from known, authorized servers.", "malicious": "Offers from unknown IPs providing malicious DNS/Gateway.", "sev": "high"},
        {"name": "Starvation Attacks", "normal": "Normal pool depletion over time.", "malicious": "Rapid pool exhaustion using many spoofed MAC addresses.", "sev": "medium"},
        {"name": "Unusual Option Fields", "normal": "Standard options (1, 3, 6, 15, 51).", "malicious": "Excessive or malformed options used for fingerprinting/overflow.", "sev": "low"},
    ],
    2328: [
        {"name": "Unexpected LSA Flooding", "normal": "Periodic LSA updates on topology change.", "malicious": "Storm of LSAs designed to consume router CPU/memory.", "sev": "high"},
        {"name": "Neighbor Spoofing", "normal": "Adjacencies with trusted local routers.", "malicious": "Spoofed HELLOs to trigger adjacency and route injection.", "sev": "high"},
        {"name": "Max Age Poisoning", "normal": "LSAs age out normally after 3600s.", "malicious": "Prematurely aging legitimate routes to cause reachability loss.", "sev": "medium"},
    ],
    2460: [
        {"name": "Extension Header Abuse", "normal": "0-1 simple extension headers.", "malicious": "Long chains of headers to hide payload from shallow inspection.", "sev": "high"},
        {"name": "Tunneling Indicators", "normal": "Standard IPv6 traffic.", "malicious": "IPv6-in-IPv4 (6to4/Teredo) used to bypass IPv4-only filters.", "sev": "medium"},
        {"name": "Unexpected ICMPv6", "normal": "Essential ND and error messages.", "malicious": "Flood of Redirects or RA to perform MitM or DoS.", "sev": "high"},
    ],
    4271: [
        {"name": "AS_PATH Anomalies", "normal": "Paths consistent with historical peering.", "malicious": "Impossibly short or circular paths; unauthorized AS inclusion.", "sev": "high"},
        {"name": "Prefix Hijacking Patterns", "normal": "Origins match authorized IRR/RPKI records.", "malicious": "Unauthorized AS announcing a more-specific or new prefix.", "sev": "high"},
        {"name": "Unusual COMMUNITY Values", "normal": "Used for standard traffic engineering.", "malicious": "Proprietary or 'blackhole' communities used to redirect traffic.", "sev": "medium"},
        {"name": "Route Leaks", "normal": "Routes stay within intended peering boundaries.", "malicious": "Propagating private peering routes to the global internet.", "sev": "medium"},
    ],
    5321: [
        {"name": "Open Relay Indicators", "normal": "Rejects mail for external domains.", "malicious": "Accepts mail from any source for any destination (spam).", "sev": "high"},
        {"name": "Header Injection", "normal": "CRLF only used to terminate lines.", "malicious": "Encoded CRLF in fields to inject 'Bcc' or 'Subject' headers.", "sev": "high"},
        {"name": "Unusual EHLO Values", "normal": "FQDN of the sending mail server.", "malicious": "Internal IPs, 'localhost', or random strings in EHLO.", "sev": "low"},
        {"name": "Bounce Flooding", "normal": "Occasional NDNs for valid delivery errors.", "malicious": "Massive volume of bounces to a spoofed 'From' address.", "sev": "medium"},
    ],
    3954: [
        {"name": "Flow Record Anomalies", "normal": "Flows match expected service patterns.", "malicious": "Unidirectional flows, many tiny flows (scanning/DDoS).", "sev": "medium"},
        {"name": "Exporter Spoofing", "normal": "NetFlow from known gateway/switch IPs.", "malicious": "Flow data from unauthorized IPs to poison telemetry.", "sev": "high"},
        {"name": "Unusual Template IDs", "normal": "Static or slowly changing templates.", "malicious": "Rapid template rotation or template exhaustion attacks.", "sev": "low"},
    ],
    7011: [
        {"name": "Flow Record Anomalies", "normal": "Flows match expected service patterns.", "malicious": "Unidirectional flows, many tiny flows (scanning/DDoS).", "sev": "medium"},
        {"name": "Exporter Spoofing", "normal": "IPFIX from known gateway/switch IPs.", "malicious": "Flow data from unauthorized IPs to poison telemetry.", "sev": "high"},
        {"name": "Unusual Template IDs", "normal": "Static or slowly changing templates.", "malicious": "Rapid template rotation or template exhaustion attacks.", "sev": "low"},
    ],
}

RELATION_RE = re.compile(r"\b(Updated by|Obsoletes|Obsoleted by):(?P<body>.*?)(?=<br\s*/?>|\n|</span>|$)", re.I | re.S)
RFC_NUM_RE = re.compile(r"\b(?:RFCs?\s*)?(\d{3,5})\b", re.I)


SITE_CSS = r"""
:root { color-scheme: dark; --bg:#070912; --panel:#0e1424; --panel2:#111a2d; --text:#eef5ff; --muted:#9fb0c9; --line:rgba(255,255,255,.11); --cyan:#65e4ff; --violet:#b89cff; --pink:#ff70b8; --green:#7dffa8; --amber:#ffd36a; }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; background: radial-gradient(circle at 12% -10%, rgba(101,228,255,.22), transparent 32rem), radial-gradient(circle at 88% 8%, rgba(184,156,255,.2), transparent 31rem), linear-gradient(135deg, #050711 0%, #09111e 48%, #100b1f 100%); color: var(--text); font: 16px/1.6 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
body:before { content:""; position: fixed; inset:0; pointer-events:none; background-image: linear-gradient(rgba(255,255,255,.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.025) 1px, transparent 1px); background-size: 44px 44px; mask-image: radial-gradient(circle at top, black, transparent 75%); }
a { color: inherit; text-decoration: none; }
.shell { width: min(1180px, calc(100% - 34px)); margin: 0 auto; }
.hero { padding: 70px 0 38px; }
.eyebrow { color: var(--cyan); text-transform: uppercase; letter-spacing: .2em; font-size: .76rem; font-weight: 800; }
h1 { margin: 12px 0 14px; font-size: clamp(2.5rem, 7vw, 6.4rem); line-height: .88; letter-spacing: -.075em; max-width: 940px; }
.hero p { max-width: 760px; color: var(--muted); font-size: 1.08rem; }
.hero strong { color: var(--text); }
.toolbar { position: sticky; top: 0; z-index: 5; padding: 16px 0; backdrop-filter: blur(18px); background: linear-gradient(to bottom, rgba(7,9,18,.92), rgba(7,9,18,.72)); border-bottom: 1px solid var(--line); }
.toolbar-row { display:grid; grid-template-columns: 1fr auto; gap: 12px; align-items:center; }
.searchbox { display:flex; gap: 12px; align-items:center; padding: 12px 16px; border: 1px solid var(--line); border-radius: 999px; background: rgba(14,20,36,.72); box-shadow: inset 0 1px 0 rgba(255,255,255,.08), 0 20px 70px rgba(0,0,0,.3); }
.searchbox span { color: var(--cyan); font-weight: 900; }
.view-count { color: var(--muted); font-weight: 800; white-space: nowrap; }
.filters { display:flex; flex-wrap:wrap; gap: 10px; margin-top: 13px; }
button.filter, button.reader-btn { cursor:pointer; color: #eaf3ff; border: 1px solid rgba(255,255,255,.13); background: rgba(255,255,255,.07); border-radius: 999px; padding: 8px 12px; font: inherit; font-size: .85rem; font-weight: 900; transition: background .18s ease, border-color .18s ease, transform .18s ease; }
button.filter:hover, button.reader-btn:hover, button.filter.active { transform: translateY(-1px); border-color: rgba(101,228,255,.55); background: rgba(101,228,255,.14); }
input { width: 100%; border: 0; outline: 0; background: transparent; color: var(--text); font: inherit; }
input::placeholder { color: #71819b; }
.stats { display:grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin: 24px 0 30px; }
.stat { border: 1px solid var(--line); border-radius: 22px; padding: 16px; background: linear-gradient(145deg, rgba(255,255,255,.08), rgba(255,255,255,.03)); min-height: 112px; }
.stat b { display:block; font-size: 1.45rem; }
.stat span { color: var(--muted); font-size: .88rem; }
.grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; padding: 6px 0 70px; }
.card { position:relative; overflow:hidden; min-height: 248px; padding: 22px; border-radius: 28px; background: linear-gradient(145deg, rgba(19,28,48,.96), rgba(11,16,30,.88)); border: 1px solid var(--line); box-shadow: 0 22px 80px rgba(0,0,0,.35); transition: transform .22s ease, border-color .22s ease, box-shadow .22s ease; }
.card:before { content:""; position:absolute; inset:-1px; opacity:.58; background: radial-gradient(circle at top right, rgba(101,228,255,.22), transparent 45%), radial-gradient(circle at bottom left, rgba(255,112,184,.16), transparent 42%); pointer-events:none; }
.card:hover { transform: translateY(-5px); border-color: rgba(101,228,255,.45); box-shadow: 0 28px 95px rgba(0,0,0,.48); }
.card.chain { border-color: rgba(255,211,106,.32); }
.card.chain:before { background: radial-gradient(circle at top right, rgba(255,211,106,.24), transparent 45%), radial-gradient(circle at bottom left, rgba(184,156,255,.18), transparent 42%); }
.card > * { position:relative; }
.num { display:inline-flex; align-items:center; gap:8px; color: var(--cyan); font-weight: 900; letter-spacing:.08em; }
.num:before { content:""; width: 9px; height: 9px; border-radius:50%; background: var(--green); box-shadow: 0 0 18px var(--green); }
.card h2 { margin: 14px 0 10px; font-size: 1.33rem; line-height: 1.16; letter-spacing: -.03em; }
.card p { margin: 0 0 20px; color: var(--muted); }
.tags, .meta-tags { display:flex; flex-wrap:wrap; gap: 8px; }
.tag { color: #dce7ff; border: 1px solid rgba(255,255,255,.13); background: rgba(255,255,255,.07); border-radius: 999px; padding: 5px 10px; font-size: .78rem; font-weight: 800; }
.tag-update-chain { color: #1b1300; border-color: rgba(255,211,106,.75); background: linear-gradient(135deg, var(--amber), #ff9f6a); }
.open { display:inline-flex; margin-top: 20px; color: var(--text); font-weight: 900; }
.open:after { content:"→"; margin-left: 8px; color: var(--pink); }
.empty { display:none; color: var(--muted); padding: 40px 0 80px; }
.toplink { color: var(--cyan); font-weight: 900; }
.progress { position: fixed; top: 0; left: 0; height: 3px; width: 0; z-index: 20; background: linear-gradient(90deg, var(--cyan), var(--pink), var(--amber)); box-shadow: 0 0 22px rgba(101,228,255,.7); }
.doc-layout { width: min(1160px, calc(100% - 32px)); margin: 0 auto; padding: 34px 0 80px; }
.reader-tools { display:flex; flex-wrap:wrap; gap: 10px; align-items:center; justify-content:space-between; margin: 18px 0; padding: 12px; border: 1px solid var(--line); border-radius: 999px; background: rgba(14,20,36,.7); }
.reader-tools .group { display:flex; flex-wrap:wrap; gap: 8px; }
.doc-hero { margin: 22px 0; padding: 28px; border: 1px solid var(--line); border-radius: 30px; background: linear-gradient(145deg, rgba(19,28,48,.95), rgba(12,17,31,.84)); }
.doc-hero h1 { font-size: clamp(2rem, 5vw, 4.7rem); max-width: none; }
.note { margin: 18px 0 0; padding: 16px 18px; border-left: 3px solid var(--cyan); border-radius: 14px; color: #dbe8ff; background: rgba(101,228,255,.08); }
.reader-grid { display:grid; grid-template-columns: minmax(0, 1fr) 270px; gap: 18px; align-items:start; }
.doc-body { overflow:auto; padding: 34px; border: 1px solid var(--line); border-radius: 26px; background: rgba(6,9,17,.84); box-shadow: 0 24px 90px rgba(0,0,0,.35); }
.doc-body.focus { max-width: 820px; margin: 0 auto; font-size: 1.05rem; }
.doc-body pre { white-space: pre-wrap; color: #d9e7ff; font: .92rem/1.55 "SFMono-Regular", Consolas, "Liberation Mono", monospace; }
.doc-body.comfy pre, .doc-body.comfy { font-size: 1.06rem; line-height: 1.75; }
.doc-body table { max-width:100%; }
.doc-body, .doc-body p, .doc-body td, .doc-body li, .doc-body pre { color: #d8e6fa; }
.doc-body a { color: var(--cyan); text-decoration: underline; }
.doc-body a.rfc-local { color: var(--green); font-weight: 900; text-decoration-color: rgba(125,255,168,.55); }
.doc-body a.rfc-external { color: var(--amber); font-weight: 900; text-decoration-style: dotted; }
.doc-body a.rfc-local:after { content:" local"; font-size:.68em; color: var(--green); text-transform: uppercase; margin-left:.25em; }
.doc-body a.rfc-external:after { content:" external"; font-size:.68em; color: var(--amber); text-transform: uppercase; margin-left:.25em; }
.doc-body h1, .doc-body h2, .doc-body h3 { color: var(--text); }
.toc-panel { position: sticky; top: 102px; max-height: calc(100vh - 130px); overflow:auto; padding: 18px; border: 1px solid var(--line); border-radius: 24px; background: rgba(14,20,36,.75); }
.toc-panel h2 { margin: 18px 0 12px; font-size: .9rem; color: var(--cyan); text-transform: uppercase; letter-spacing:.14em; }
.toc-panel a { display:block; color: var(--muted); font-size: .88rem; line-height:1.25; padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,.06); }
.toc-panel a:hover { color: var(--text); }
.toc-panel .muted { color: var(--muted); font-size:.88rem; }
.header-reference-panel { margin: 0 0 18px; border: 1px solid rgba(101,228,255,.24); border-radius: 20px; background: linear-gradient(145deg, rgba(101,228,255,.10), rgba(255,112,184,.05)); overflow:hidden; }
.header-reference-panel summary { cursor:pointer; list-style:none; padding: 14px 15px; border-bottom: 1px solid rgba(255,255,255,.08); }
.header-reference-panel summary::-webkit-details-marker { display:none; }
.header-reference-panel summary span { display:block; color: var(--cyan); text-transform: uppercase; letter-spacing:.13em; font-size:.66rem; font-weight:900; }
.header-reference-panel summary strong { display:block; margin-top: 4px; color: var(--text); font-size:.94rem; line-height:1.2; }
.header-reference-panel summary:after { content:"▾"; float:right; margin-top:-28px; color: var(--pink); font-weight:900; }
.header-reference-panel:not([open]) summary { border-bottom:0; }
.header-reference-panel:not([open]) summary:after { content:"▸"; }
.header-note { margin: 12px 14px; color:#dbe8ff; font-size:.83rem; line-height:1.45; }
.bit-axis { margin: 0 14px 6px; color: var(--muted); font-size:.72rem; font-weight:900; letter-spacing:.08em; text-transform:uppercase; }
.header-diagram-wrap { margin: 0 12px 14px; overflow-x:auto; padding: 10px; border: 1px solid rgba(255,255,255,.10); border-radius: 16px; background: rgba(5,7,17,.58); }
.header-bit-layout { min-width: 320px; width:100%; height:auto; display:block; }
.bit-label { fill:#9fb0c9; font: 10px ui-monospace, SFMono-Regular, Consolas, monospace; }
.bit-grid { stroke: rgba(255,255,255,.13); stroke-width: 1; }
.field-block { stroke: rgba(255,255,255,.28); stroke-width: 1; }
.field-0 { fill: rgba(101,228,255,.38); }
.field-1 { fill: rgba(184,156,255,.38); }
.field-2 { fill: rgba(255,112,184,.32); }
.field-3 { fill: rgba(125,255,168,.28); }
.field-4 { fill: rgba(255,211,106,.32); }
.field-label { fill:#f6fbff; font: 9px ui-monospace, SFMono-Regular, Consolas, monospace; font-weight:800; pointer-events:none; }
.header-field-table { width: calc(100% - 24px); margin: 0 12px 14px; border-collapse: collapse; font-size:.75rem; line-height:1.35; }
.header-field-table th, .header-field-table td { padding: 7px 6px; border-top: 1px solid rgba(255,255,255,.08); vertical-align:top; }
.header-field-table th { color: var(--cyan); text-align:left; font-size:.68rem; text-transform:uppercase; letter-spacing:.08em; }
.header-field-table td:nth-child(2) { color: var(--amber); font-weight:900; white-space:nowrap; }
footer { color: var(--muted); border-top: 1px solid var(--line); padding: 28px 0 50px; }
@media (max-width: 980px) { .reader-grid { grid-template-columns: 1fr; } .toc-panel { position:relative; top:auto; max-height:none; order:-1; } }
@media (max-width: 780px) { .toolbar-row { grid-template-columns: 1fr; } .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); } .hero { padding-top: 46px; } .doc-body, .doc-hero { padding: 20px; border-radius: 22px; } .reader-tools { border-radius: 22px; } .header-field-table { font-size:.72rem; } }

/* Flashcard SRS Overlay */
.study-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  background: var(--bg);
  z-index: 9999;
  display: none;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.study-overlay.active { display: flex; }
.study-header {
  position: absolute;
  top: 20px;
  width: min(800px, 100%);
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: var(--muted);
  font-size: 0.9rem;
}
.study-progress-bar {
  position: absolute;
  top: 0;
  left: 0;
  height: 4px;
  background: var(--cyan);
  transition: width 0.3s;
}
.card-container {
  width: min(600px, 100%);
  height: 400px;
  perspective: 1000px;
  cursor: pointer;
}
.flashcard {
  position: relative;
  width: 100%;
  height: 100%;
  text-align: center;
  transition: transform 0.6s;
  transform-style: preserve-3d;
}
.card-container.flipped .flashcard { transform: rotateY(180deg); }
.card-face {
  position: absolute;
  width: 100%;
  height: 100%;
  backface-visibility: hidden;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px;
  border-radius: 32px;
  border: 2px solid var(--line);
  background: var(--panel);
  box-shadow: 0 30px 100px rgba(0,0,0,0.5);
}
.card-back {
  transform: rotateY(180deg);
  border-color: var(--cyan);
}
.card-category {
  position: absolute;
  top: 30px;
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.2em;
  color: var(--cyan);
  font-weight: 800;
}
.card-prompt {
  font-size: 1.8rem;
  font-weight: 800;
  line-height: 1.2;
  margin: 20px 0;
}
.card-answer {
  font-size: 1.1rem;
  line-height: 1.6;
  color: var(--text);
  max-width: 100%;
  overflow-y: auto;
}
.card-meta {
  position: absolute;
  bottom: 30px;
  font-size: 0.7rem;
  color: var(--muted);
}
.study-actions {
  margin-top: 40px;
  display: none;
  gap: 15px;
}
.study-actions.visible { display: flex; }
.srs-btn {
  padding: 12px 24px;
  border-radius: 999px;
  border: none;
  font-weight: 900;
  cursor: pointer;
  font-size: 0.9rem;
  transition: transform 0.2s;
}
.srs-btn:hover { transform: translateY(-2px); }
.btn-again { background: var(--pink); color: var(--bg); }
.btn-hard { background: var(--amber); color: var(--bg); }
.btn-good { background: var(--cyan); color: var(--bg); }
.btn-easy { background: var(--green); color: var(--bg); }

.study-summary {
  text-align: center;
  display: none;
}
.study-summary.active { display: block; }
.summary-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 20px;
  margin: 30px 0;
}
.summary-stat {
  padding: 20px;
  background: var(--panel2);
  border-radius: 20px;
  border: 1px solid var(--line);
}
.summary-stat b { display: block; font-size: 2rem; color: var(--cyan); }

.badge {
  background: var(--pink);
  color: var(--bg);
  font-size: 0.65rem;
  font-weight: 900;
  padding: 2px 6px;
  border-radius: 6px;
  margin-left: 8px;
  vertical-align: middle;
}
.study-progress-card {
  background: linear-gradient(145deg, rgba(101,228,255,0.1), rgba(184,156,255,0.05));
  border: 1px solid rgba(101,228,255,0.2);
  grid-column: span 2;
}
.study-progress-card .btn-group { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
.study-progress-card .reader-btn { flex: 1; min-width: fit-content; white-space: nowrap; }
.study-hint {
  position: absolute;
  bottom: 20px;
  color: var(--muted);
  font-size: 0.8rem;
}
"""


INDEX_JS = r"""
const q = document.querySelector('#q');
const cards = [...document.querySelectorAll('.card')];
const empty = document.querySelector('.empty');
const count = document.querySelector('#count');
const filters = [...document.querySelectorAll('.filter')];
const viewNotesBtn = document.querySelector('#view-notes');
const backToGridBtn = document.querySelector('#back-to-grid');
const notesView = document.querySelector('#notes-view');
const mainGrid = document.querySelector('main');
const notesContainer = document.querySelector('#notes-container');
const exportBtn = document.querySelector('#export-notes');
const importBtn = document.querySelector('#import-notes-btn');
const importFile = document.querySelector('#import-notes-file');
const noteFilterBtns = [...document.querySelectorAll('.notes-filter-btn')];

// FSRS Study Mode
const studyOverlay = document.querySelector('#study-overlay');
const startStudyBtn = document.querySelector('#start-study');
const studyAllBtn = document.querySelector('#study-all');
const closeStudyBtn = document.querySelector('#close-study');
const cardContainer = document.querySelector('#card-container');
const studyActions = document.querySelector('#study-actions');
const studySummary = document.querySelector('#study-summary');
const progressBar = document.querySelector('#study-progress-bar');
const srsDueBadge = document.querySelector('#srs-due-count');

let activeTag = 'all';
let activeNoteFilter = 'all';
let currentSession = [];
let sessionIdx = 0;
let sessionStats = { reviewed: 0, mastered: 0, dueTomorrow: 0 };

const w = [0.4, 0.6, 2.4, 5.8, 4.93, 0.94, 0.86, 0.01, 1.49, 0.14, 0.94, 2.18, 0.05, 0.34, 1.26, 0.29, 2.61];

function getSRSData() {
  return JSON.parse(localStorage.getItem('rfc_srs_state_fsrs') || '{}');
}

function saveSRSData(state) {
  localStorage.setItem('rfc_srs_state_fsrs', JSON.stringify(state));
  updateDueCounts();
}

function getRetrievability(state, now) {
  if (!state || !state.last_date) return 0;
  const t = Math.max(0, (now - state.last_date) / (24 * 60 * 60 * 1000));
  return Math.pow(1 + t / (9 * state.S), -1);
}

function fsrs_update(grade, state, now) {
  let { S, D, last_date, repetitions } = state || { S: 0, D: 0, last_date: 0, repetitions: 0 };
  if (repetitions === 0) {
    S = w[grade - 1]; D = w[4] - (grade - 3) * w[5];
  } else {
    D = Math.min(Math.max(D - w[6] * (grade - 3), 1), 10);
    const R = getRetrievability(state, now);
    if (grade === 1) { S = w[7] * Math.exp(-w[8] * D) * (Math.pow(S + 1, w[9]) - 1) * Math.exp(w[10] * (1 - R)); }
    else { S = S * (1 + Math.exp(w[11]) * (11 - D) * Math.pow(S, -w[12]) * (Math.exp(w[13] * (1 - R)) - 1)); }
  }
  repetitions++;
  return { S, D, last_date: now, repetitions };
}

function updateDueCounts() {
  const srs = getSRSData(); const now = Date.now();
  const due = (window.FLASHCARDS || []).filter(c => {
    const state = srs[c.id]; if (!state) return true;
    return getRetrievability(state, now) <= 0.9;
  });
  if (srsDueBadge) srsDueBadge.textContent = due.length;
}

function initStudySession(all = false) {
  const srs = getSRSData(); const now = Date.now();
  currentSession = (window.FLASHCARDS || []).filter(c => {
    if (all) return true;
    const state = srs[c.id]; if (!state) return true;
    return getRetrievability(state, now) <= 0.9;
  });
  if (currentSession.length === 0 && !all) { alert("No cards due! Use 'Study All' to practice anyway."); return; }
  currentSession.sort(() => Math.random() - 0.5);
  sessionIdx = 0; sessionStats = { reviewed: 0, mastered: 0, dueTomorrow: 0 };
  studyOverlay.classList.add('active'); studySummary.classList.remove('active');
  cardContainer.style.display = 'block'; showCard();
}

function showCard() {
  if (sessionIdx >= currentSession.length) { showSummary(); return; }
  const card = currentSession[sessionIdx]; const state = getSRSData()[card.id];
  const R = state ? Math.round(getRetrievability(state, Date.now()) * 100) : 0;
  cardContainer.classList.remove('flipped'); studyActions.classList.remove('visible');
  document.querySelector('#card-category').textContent = card.category;
  document.querySelector('#card-category-back').textContent = card.category;
  document.querySelector('#card-prompt').textContent = card.prompt;
  document.querySelector('#card-answer').textContent = card.answer;
  document.querySelector('#card-meta').textContent = state ? `S: ${state.S.toFixed(1)} | D: ${state.D.toFixed(1)} | R: ${R}%` : 'New Card';
  document.querySelector('#study-count').textContent = `Card ${sessionIdx + 1} of ${currentSession.length}`;
  progressBar.style.width = `${(sessionIdx / currentSession.length) * 100}%`;
}

function showSummary() {
  cardContainer.style.display = 'none'; studyActions.classList.remove('visible'); studySummary.classList.add('active');
  progressBar.style.width = '100%';
  document.querySelector('#sum-reviewed').textContent = sessionStats.reviewed;
  document.querySelector('#sum-mastered').textContent = sessionStats.mastered;
  const srs = getSRSData(); const tomorrow = Date.now() + 24*60*60*1000;
  const dueTomorrow = Object.values(srs).filter(s => getRetrievability(s, tomorrow) <= 0.9).length;
  document.querySelector('#sum-due').textContent = dueTomorrow;
}

function handleAnswer(grade) {
  const card = currentSession[sessionIdx]; const srs = getSRSData();
  const newState = fsrs_update(grade, srs[card.id], Date.now());
  srs[card.id] = newState; saveSRSData(srs);
  sessionStats.reviewed++; if (newState.S > 30) sessionStats.mastered++;
  sessionIdx++; showCard();
}

if (cardContainer) {
    cardContainer.addEventListener('click', () => {
      if (!cardContainer.classList.contains('flipped')) { cardContainer.classList.add('flipped'); studyActions.classList.add('visible'); }
    });
}

document.querySelectorAll('.srs-btn').forEach(btn => {
  btn.addEventListener('click', (e) => { e.stopPropagation(); handleAnswer(parseInt(btn.dataset.quality)); });
});

if (closeStudyBtn) closeStudyBtn.addEventListener('click', () => studyOverlay.classList.remove('active'));
document.querySelector('#finish-study').addEventListener('click', () => studyOverlay.classList.remove('active'));
document.querySelector('#restart-study').addEventListener('click', () => initStudySession());
if (startStudyBtn) startStudyBtn.addEventListener('click', () => initStudySession(false));
if (studyAllBtn) studyAllBtn.addEventListener('click', () => initStudySession(true));

const resetSrsBtn = document.querySelector(\"#reset-srs\");
if (resetSrsBtn) resetSrsBtn.addEventListener(\"click\", () => { if(confirm(\"Wipe all FSRS progress?\")) { localStorage.removeItem(\"rfc_srs_state_fsrs\"); location.reload(); } });

window.addEventListener('keydown', (e) => {
  if (!studyOverlay || !studyOverlay.classList.contains('active')) return;
  if (e.key === 'Escape') studyOverlay.classList.remove('active');
  if (e.key === ' ') { if (!cardContainer.classList.contains('flipped')) cardContainer.click(); }
  if (cardContainer.classList.contains('flipped')) {
    if (e.key === '1') handleAnswer(1); if (e.key === '2') handleAnswer(2); if (e.key === '3') handleAnswer(3); if (e.key === '4') handleAnswer(4);
  }
});

// Relationship Map Logic
const mapOverlay = document.querySelector('#map-overlay');
const openMapBtn = document.querySelector('#open-map');
const closeMapBtn = document.querySelector('#close-map');
const mapContainer = document.querySelector('#map-container');

const GRAPH_DATA = {
  get nodes() {
    return (window.FLASHCARDS || []).filter(c => c.id.endsWith('-fundamental')).map(c => ({
        id: c.rfc, num: c.rfc,
        name: c.prompt.match(/RFC \d+ \((.*?)\)/)?.[1] || `RFC ${c.rfc}`,
        layer: c.answer.match(/Layer: (.*?)\n/)?.[1].split(',')[0].trim().toLowerCase() || 'application'
    }));
  },
  links: [
    { source: \"793\", target: \"791\", type: \"dependency\" }, { source: \"768\", target: \"791\", type: \"dependency\" },
    { source: \"1035\", target: \"768\", type: \"dependency\" }, { source: \"1035\", target: \"793\", type: \"dependency\" },
    { source: \"4271\", target: \"793\", type: \"dependency\" }, { source: \"2131\", target: \"768\", type: \"dependency\" },
    { source: \"5321\", target: \"793\", type: \"dependency\" }, { source: \"3954\", target: \"768\", type: \"dependency\" },
    { source: \"7011\", target: \"768\", type: \"dependency\" }, { source: \"2616\", target: \"793\", type: \"dependency\" },
    { source: \"7230\", target: \"793\", type: \"dependency\" }, { source: \"7540\", target: \"793\", type: \"dependency\" },
    { source: \"2328\", target: \"791\", type: \"dependency\" }, { source: \"826\", target: \"791\", type: \"dependency\" },
    { source: \"2460\", target: \"791\", type: \"update-chain\" }, { source: \"7230\", target: \"2616\", type: \"update-chain\" },
    { source: \"1035\", target: \"5321\", type: \"threat\" }, { source: \"1035\", target: \"768\", type: \"threat\" },
    { source: \"4271\", target: \"2328\", type: \"threat\" }, { source: \"791\", target: \"2460\", type: \"threat\" },
    { source: \"793\", target: \"7540\", type: \"threat\" },
  ]
};

function initMap() {
  if (!window.d3) { console.error(\"D3 not loaded\"); return; }
  const nodes = GRAPH_DATA.nodes; if (!nodes.length) { console.warn(\"No nodes found\"); return; }
  const nodeIds = new Set(nodes.map(n => n.id));
  const links = GRAPH_DATA.links.filter(l => nodeIds.has(l.source) && nodeIds.has(l.target)).map(l => ({...l}));
  
  const width = mapContainer.clientWidth || window.innerWidth;
  const height = mapContainer.clientHeight || window.innerHeight;
  
  d3.select(\"#map-container svg\").remove();
  const svg = d3.select(\"#map-container\").append(\"svg\")
    .attr(\"width\", \"100%\").attr(\"height\", \"100%\").attr(\"viewBox\", [0, 0, width, height]);
  const g = svg.append(\"g\");

  svg.call(d3.zoom().extent([[0, 0], [width, height]]).scaleExtent([0.1, 8]).on(\"zoom\", ({transform}) => g.attr(\"transform\", transform)));

  const simulation = d3.forceSimulation(nodes)
    .force(\"link\", d3.forceLink(links).id(d => d.id).distance(150))
    .force(\"charge\", d3.forceManyBody().strength(-400))
    .force(\"center\", d3.forceCenter(width / 2, height / 2))
    .force(\"collision\", d3.forceCollide().radius(70));

  const link = g.append(\"g\").selectAll(\"path\").data(links).join(\"path\").attr(\"class\", d => `link ${d.type}`);
  const node = g.append(\"g\").selectAll(\".node\").data(nodes).join(\"g\").attr(\"class\", d => `node node-${d.layer}`)
    .call(d3.drag().on(\"start\", (e) => { if (!e.active) simulation.alphaTarget(0.3).restart(); e.subject.fx = e.subject.x; e.subject.fy = e.subject.y; })
      .on(\"drag\", (e) => { e.subject.fx = e.x; e.subject.fy = e.y; })
      .on(\"end\", (e) => { if (!e.active) simulation.alphaTarget(0); e.subject.fx = null; e.subject.fy = null; }))
    .on(\"click\", (e, d) => { if (e.defaultPrevented) return; window.location.href = `rfc/rfc${d.num}.html`; })
    .on(\"mouseover\", (e, d) => {
      const neighbors = new Set([d.id]);
      links.forEach(l => { 
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        if (s === d.id) neighbors.add(t); if (t === d.id) neighbors.add(s);
      });
      node.classed(\"dimmed\", n => !neighbors.has(n.id));
      link.classed(\"dimmed\", l => {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        return s !== d.id && t !== d.id;
      });
      link.classed(\"highlight\", l => {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        return s === d.id || t === d.id;
      });
    }).on(\"mouseout\", () => { node.classed(\"dimmed\", false); link.classed(\"dimmed\", false); link.classed(\"highlight\", false); });

  node.append(\"rect\").attr(\"width\", 100).attr(\"height\", 45).attr(\"x\", -50).attr(\"y\", -22);
  node.append(\"text\").attr(\"dy\", \"-2\").text(d => d.name.length > 15 ? d.name.substring(0, 13) + '...' : d.name);
  node.append(\"text\").attr(\"class\", \"node-rfc\").attr(\"dy\", \"12\").text(d => `RFC ${d.num}`);

  simulation.on(\"tick\", () => {
    link.attr(\"d\", d => {
      const dx = d.target.x - d.source.x, dy = d.target.y - d.source.y;
      const dr = Math.sqrt(dx * dx + dy * dy);
      return `M${d.source.x},${d.source.y}A${dr},${dr} 0 0,1 ${d.target.x},${d.target.y}`;
    });
    node.attr(\"transform\", d => `translate(${d.x},${d.y})`);
  });
}

if (openMapBtn) openMapBtn.addEventListener('click', () => { mapOverlay.classList.add('active'); setTimeout(initMap, 100); });
if (closeMapBtn) closeMapBtn.addEventListener('click', () => mapOverlay.classList.remove('active'));

window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && mapOverlay.classList.contains('active')) mapOverlay.classList.remove('active');
});

function applyFilters() {
  const term = q.value.trim().toLowerCase();
  let visible = 0;
  for (const card of cards) {
    const tagHit = activeTag === 'all' || card.dataset.tags.split(' ').includes(activeTag);
    const hit = tagHit && card.dataset.search.includes(term);
    card.style.display = hit ? '' : 'none';
    if (hit) visible++;
  }
  count.textContent = `${visible} shown`; empty.style.display = visible ? 'none' : 'block';
}

function renderNotes() {
  const allNotes = JSON.parse(localStorage.getItem('rfc_notes') || '{}');
  notesContainer.innerHTML = '';
  const rfcNums = Object.keys(allNotes).sort((a, b) => parseInt(a) - parseInt(b));
  let hasVisibleNotes = false;
  rfcNums.forEach(num => {
    const sectionIds = Object.keys(allNotes[num]).sort();
    const filteredSids = sectionIds.filter(sid => activeNoteFilter === 'all' || allNotes[num][sid].type === activeNoteFilter);
    if (filteredSids.length === 0) return;
    hasVisibleNotes = true;
    const rfcGroup = document.createElement('div'); rfcGroup.className = 'notes-rfc-group';
    const firstNoteId = filteredSids[0];
    const rfcTitle = allNotes[num][firstNoteId].rfcTitle || `RFC ${num}`;
    const header = document.createElement('div'); header.className = 'notes-rfc-header';
    header.innerHTML = `<span>RFC ${num}: ${rfcTitle}</span> <a href=\"rfc/rfc${num}.html\">View RFC</a>`;
    rfcGroup.appendChild(header);
    filteredSids.forEach(sid => {
      const note = allNotes[num][sid];
      const item = document.createElement('div'); item.className = 'note-item';
      const link = document.createElement('a'); link.className = 'note-item-link';
      link.href = `rfc/rfc${num}.html#${sid}`; link.textContent = note.title || `Section ${sid}`;
      const content = document.createElement('div'); content.className = 'note-item-content';
      content.textContent = note.content; item.appendChild(link); item.appendChild(content); rfcGroup.appendChild(item);
    });
    notesContainer.appendChild(rfcGroup);
  });
  if (!hasVisibleNotes) {
    notesContainer.innerHTML = rfcNums.length === 0 ? '<div class=\"notes-empty\">You haven\'t added any notes yet.</div>' : `<div class=\"notes-empty\">No notes match the \"${activeNoteFilter}\" filter.</div>`;
  }
}

function toggleNotesView(show) {
  if (show) {
    mainGrid.style.display = 'none'; document.querySelector('.hero').style.display = 'none';
    document.querySelector('.toolbar').style.display = 'none'; notesView.classList.add('active'); renderNotes();
  } else {
    mainGrid.style.display = 'block'; document.querySelector('.hero').style.display = 'block';
    document.querySelector('.toolbar').style.display = 'block'; notesView.classList.remove('active');
  }
}

q.addEventListener('input', applyFilters);
filters.forEach(btn => btn.addEventListener('click', () => { activeTag = btn.dataset.tag; filters.forEach(item => item.classList.toggle('active', item === btn)); applyFilters(); }));
noteFilterBtns.forEach(btn => btn.addEventListener('click', () => { activeNoteFilter = btn.dataset.filter; noteFilterBtns.forEach(b => b.classList.toggle('active', b === btn)); renderNotes(); }));
viewNotesBtn.addEventListener('click', () => toggleNotesView(true));
backToGridBtn.addEventListener('click', () => toggleNotesView(false));
exportBtn.addEventListener('click', () => {
  const allNotes = localStorage.getItem('rfc_notes') || '{}';
  const blob = new Blob([allNotes], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = `rfc-annotations-${new Date().toISOString().split('T')[0]}.json`; a.click(); URL.revokeObjectURL(url);
});
importBtn.addEventListener('click', () => importFile.click());
importFile.addEventListener('change', (e) => {
  const file = e.target.files[0]; if (!file) return;
  const reader = new FileReader();
  reader.onload = (event) => {
    try {
      const imported = JSON.parse(event.target.result);
      const current = JSON.parse(localStorage.getItem('rfc_notes') || '{}');
      for (const rfcNum in imported) {
        if (!current[rfcNum]) current[rfcNum] = imported[rfcNum];
        else current[rfcNum] = { ...current[rfcNum], ...imported[rfcNum] };
      }
      localStorage.setItem('rfc_notes', JSON.stringify(current)); renderNotes(); alert('Notes imported and merged successfully!');
    } catch (err) { alert('Error importing notes: Invalid JSON file'); }
  };
  reader.readAsText(file);
});

updateDueCounts();
applyFilters();
"""


DOC_JS = r"""
const progress = document.querySelector('.progress');
const body = document.querySelector('.doc-body');
const toc = document.querySelector('#toc-links');
const focusBtn = document.querySelector('[data-action="focus"]');
const comfyBtn = document.querySelector('[data-action="comfy"]');
const topBtn = document.querySelector('[data-action="top"]');
const headerPanel = document.querySelector('.header-reference-panel');

const rfcMatch = document.querySelector('.eyebrow')?.textContent.match(/RFC (\d+)/);
const rfcNumber = rfcMatch ? rfcMatch[1] : null;

// FSRS Study Mode
const studyOverlay = document.querySelector('#study-overlay');
const studyRfcBtn = document.querySelector('#study-rfc');
const studyBadge = document.querySelector('#study-badge');
const closeStudyBtn = document.querySelector('#close-study');
const cardContainer = document.querySelector('#card-container');
const studyActions = document.querySelector('#study-actions');
const studySummary = document.querySelector('#study-summary');
const progressBar = document.querySelector('#study-progress-bar');

let currentSession = [];
let sessionIdx = 0;
let sessionStats = { reviewed: 0, mastered: 0, dueTomorrow: 0 };

const w = [0.4, 0.6, 2.4, 5.8, 4.93, 0.94, 0.86, 0.01, 1.49, 0.14, 0.94, 2.18, 0.05, 0.34, 1.26, 0.29, 2.61];

function getSRSData() {
  return JSON.parse(localStorage.getItem('rfc_srs_state_fsrs') || '{}');
}

function saveSRSData(state) {
  localStorage.setItem('rfc_srs_state_fsrs', JSON.stringify(state));
  updateDueBadge();
}

function getRetrievability(state, now) {
  if (!state || !state.last_date) return 0;
  const t = Math.max(0, (now - state.last_date) / (24 * 60 * 60 * 1000));
  return Math.pow(1 + t / (9 * state.S), -1);
}

function fsrs_update(grade, state, now) {
  let { S, D, last_date, repetitions } = state || { S: 0, D: 0, last_date: 0, repetitions: 0 };
  if (repetitions === 0) {
    S = w[grade - 1]; D = w[4] - (grade - 3) * w[5];
  } else {
    D = Math.min(Math.max(D - w[6] * (grade - 3), 1), 10);
    const R = getRetrievability(state, now);
    if (grade === 1) { S = w[7] * Math.exp(-w[8] * D) * (Math.pow(S + 1, w[9]) - 1) * Math.exp(w[10] * (1 - R)); }
    else { S = S * (1 + Math.exp(w[11]) * (11 - D) * Math.pow(S, -w[12]) * (Math.exp(w[13] * (1 - R)) - 1)); }
  }
  repetitions++;
  return { S, D, last_date: now, repetitions };
}

function updateDueBadge() {
  if (!studyBadge || !rfcNumber) return;
  const srs = getSRSData(); const now = Date.now();
  const due = (window.FLASHCARDS || []).filter(c => {
    if (c.rfc !== rfcNumber) return false;
    const state = srs[c.id]; if (!state) return true;
    return getRetrievability(state, now) <= 0.9;
  });
  studyBadge.textContent = due.length || '';
  studyBadge.style.display = due.length ? 'inline-block' : 'none';
}

function initStudySession(all = false) {
  const srs = getSRSData(); const now = Date.now();
  currentSession = (window.FLASHCARDS || []).filter(c => {
    if (c.rfc !== rfcNumber) return false;
    if (all) return true;
    const state = srs[c.id]; if (!state) return true;
    return getRetrievability(state, now) <= 0.9;
  });
  if (currentSession.length === 0 && !all) {
    alert("No cards due for this RFC! Click again to study all cards for this RFC.");
    studyRfcBtn.onclick = () => initStudySession(true);
    return;
  }
  currentSession.sort(() => Math.random() - 0.5);
  sessionIdx = 0; sessionStats = { reviewed: 0, mastered: 0, dueTomorrow: 0 };
  studyOverlay.classList.add('active'); studySummary.classList.remove('active');
  cardContainer.style.display = 'block'; showCard();
}

function showCard() {
  if (sessionIdx >= currentSession.length) { showSummary(); return; }
  const card = currentSession[sessionIdx]; const state = getSRSData()[card.id];
  const R = state ? Math.round(getRetrievability(state, Date.now()) * 100) : 0;
  cardContainer.classList.remove('flipped'); studyActions.classList.remove('visible');
  document.querySelector('#card-category').textContent = card.category;
  document.querySelector('#card-category-back').textContent = card.category;
  document.querySelector('#card-prompt').textContent = card.prompt;
  document.querySelector('#card-answer').textContent = card.answer;
  document.querySelector('#card-meta').textContent = state ? `S: ${state.S.toFixed(1)} | D: ${state.D.toFixed(1)} | R: ${R}%` : 'New Card';
  document.querySelector('#study-count').textContent = `Card ${sessionIdx + 1} of ${currentSession.length}`;
  progressBar.style.width = `${(sessionIdx / currentSession.length) * 100}%`;
}

function showSummary() {
  cardContainer.style.display = 'none'; studyActions.classList.remove('visible'); studySummary.classList.add('active');
  progressBar.style.width = '100%';
  document.querySelector('#sum-reviewed').textContent = sessionStats.reviewed;
  document.querySelector('#sum-mastered').textContent = sessionStats.mastered;
  const srs = getSRSData(); const tomorrow = Date.now() + 24*60*60*1000;
  const dueTomorrow = Object.values(srs).filter(s => getRetrievability(s, tomorrow) <= 0.9).length;
  document.querySelector('#sum-due').textContent = dueTomorrow;
}

function handleAnswer(grade) {
  const card = currentSession[sessionIdx]; const srs = getSRSData();
  const newState = fsrs_update(grade, srs[card.id], Date.now());
  srs[card.id] = newState; saveSRSData(srs);
  sessionStats.reviewed++; if (newState.S > 30) sessionStats.mastered++;
  sessionIdx++; showCard();
}

if (cardContainer) {
    cardContainer.addEventListener('click', () => {
      if (!cardContainer.classList.contains('flipped')) { cardContainer.classList.add('flipped'); studyActions.classList.add('visible'); }
    });
}

document.querySelectorAll('.srs-btn').forEach(btn => {
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    handleAnswer(parseInt(btn.dataset.quality));
  });
});

if (closeStudyBtn) closeStudyBtn.addEventListener('click', () => studyOverlay.classList.remove('active'));
document.querySelector('#finish-study').addEventListener('click', () => studyOverlay.classList.remove('active'));
document.querySelector('#restart-study').addEventListener('click', () => initStudySession());
if (studyRfcBtn) studyRfcBtn.addEventListener('click', () => initStudySession(false));

const resetSrsBtn = document.querySelector("#reset-srs");
if (resetSrsBtn) resetSrsBtn.addEventListener("click", () => { if(confirm("Wipe all FSRS progress?")) { localStorage.removeItem("rfc_srs_state_fsrs"); location.reload(); } });

window.addEventListener('keydown', (e) => {
  if (!studyOverlay || !studyOverlay.classList.contains('active')) return;
  if (e.key === 'Escape') studyOverlay.classList.remove('active');
  if (e.key === ' ') { if (!cardContainer.classList.contains('flipped')) cardContainer.click(); }
  if (cardContainer.classList.contains('flipped')) {
    if (e.key === '1') handleAnswer(1); if (e.key === '2') handleAnswer(2); if (e.key === '3') handleAnswer(3); if (e.key === '4') handleAnswer(4);
  }
});

// Relationship Map Logic (minimal to avoid issues)
const mapOverlay = document.querySelector('#map-overlay');
const openMapBtn = document.querySelector('#open-map');
const closeMapBtn = document.querySelector('#close-map');
const mapContainer = document.querySelector('#map-container');

function updateProgress() {
  const max = document.documentElement.scrollHeight - innerHeight;
  progress.style.width = max > 0 ? `${(scrollY / max) * 100}%` : '0%';
}

function makeToc() {
  let headingNodes = [...document.querySelectorAll('h1, h2, h3, .doc-body span > a[href^="#section-"], .threat-item')].slice(0, 100);
  if (!headingNodes.length) {
    toc.innerHTML = '<p class="muted">This RFC source is mostly preformatted text, so use browser find for section jumps.</p>';
    return [];
  }
  headingNodes = headingNodes.filter(el => !el.closest('.doc-hero'));
  const headings = headingNodes.map(el => {
    if (el.tagName === 'A' && el.parentElement && el.parentElement.tagName === 'SPAN') return el.parentElement;
    return el;
  });
  toc.innerHTML = '';
  headings.forEach((heading, index) => {
    if (heading.classList.contains('threat-item')) return;
    if (!heading.id) { heading.id = `section-${index + 1}`; }
    const id = heading.id;
    const link = document.createElement('a');
    link.href = `#${id}`;
    link.textContent = heading.textContent.replace('Note', '').trim().slice(0, 96) || `Section ${index + 1}`;
    toc.appendChild(link);
  });
  return headings;
}

function initAnnotations(headings) {
  if (!rfcNumber || !headings || !headings.length) return;
  const allNotes = JSON.parse(localStorage.getItem('rfc_notes') || '{}');
  const rfcNotes = allNotes[rfcNumber] || {};
  headings.forEach((heading) => {
    const sectionId = heading.id;
    const isThreatItem = heading.classList.contains('threat-item');
    const existingNote = rfcNotes[sectionId]?.content || '';
    const toggle = document.createElement('button');
    toggle.className = 'anno-toggle';
    toggle.textContent = 'Note';
    toggle.title = 'Toggle annotation';
    if (isThreatItem) { heading.querySelector('.threat-header').appendChild(toggle); }
    else { heading.appendChild(toggle); }
    const indicator = document.createElement('span');
    indicator.className = 'anno-indicator';
    indicator.style.display = existingNote ? 'inline-block' : 'none';
    if (isThreatItem) { heading.querySelector('.threat-header').appendChild(indicator); }
    else { heading.appendChild(indicator); }
    const wrap = document.createElement('div');
    wrap.className = 'anno-editor-wrap';
    if (existingNote) { toggle.classList.add('active'); }
    const editor = document.createElement('textarea');
    editor.className = 'anno-editor';
    editor.placeholder = 'Add your notes for this ' + (isThreatItem ? 'indicator' : 'section') + '...';
    editor.value = existingNote;
    const status = document.createElement('div');
    status.className = 'anno-status';
    status.textContent = 'Saved';
    wrap.appendChild(editor);
    wrap.appendChild(status);
    if (isThreatItem) { heading.appendChild(wrap); }
    else { heading.insertAdjacentElement('afterend', wrap); }
    toggle.addEventListener('click', (e) => {
      e.preventDefault(); e.stopPropagation();
      const isVisible = wrap.classList.toggle('visible');
      toggle.classList.toggle('active', isVisible || editor.value.trim() !== '');
      if (isVisible) editor.focus();
    });
    editor.addEventListener('blur', () => {
      const content = editor.value.trim();
      const allNotes = JSON.parse(localStorage.getItem('rfc_notes') || '{}');
      if (!allNotes[rfcNumber]) allNotes[rfcNumber] = {};
      if (content) {
        let title = '';
        if (isThreatItem) { title = 'Threat: ' + heading.querySelector('.threat-name').textContent; }
        else { title = heading.textContent.replace('Note', '').trim(); }
        allNotes[rfcNumber][sectionId] = {
          content: content, title: title,
          rfcTitle: document.title.split(':')[1]?.trim() || `RFC ${rfcNumber}`,
          timestamp: Date.now(), type: isThreatItem ? 'threat' : 'section'
        };
        indicator.style.display = 'inline-block';
        toggle.classList.add('active');
      } else {
        delete allNotes[rfcNumber][sectionId];
        if (Object.keys(allNotes[rfcNumber]).length === 0) { delete allNotes[rfcNumber]; }
        indicator.style.display = 'none';
        toggle.classList.remove('active');
      }
      localStorage.setItem('rfc_notes', JSON.stringify(allNotes));
      status.classList.add('visible');
      setTimeout(() => status.classList.remove('visible'), 2000);
    });
  });
}

function setHeaderPanelDefault() {
  if (!headerPanel) return;
  headerPanel.open = !matchMedia('(max-width: 780px)').matches;
}

addEventListener('scroll', updateProgress, { passive: true });
if (focusBtn) focusBtn.addEventListener('click', () => body.classList.toggle('focus'));
if (comfyBtn) comfyBtn.addEventListener('click', () => body.classList.toggle('comfy'));
if (topBtn) topBtn.addEventListener('click', () => scrollTo({ top: 0, behavior: 'smooth' }));
setHeaderPanelDefault();
const headings = makeToc();
initAnnotations(headings);
updateProgress();
updateDueBadge();
"""


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


def extract_title(build: RFCBuild) -> str:
    if build.html_ok and build.html_path:
        raw = read_text(build.html_path)
        match = re.search(r"<title>\s*RFC\s+\d+\s*:?\s*(.*?)\s*</title>", raw, flags=re.I | re.S)
        if match:
            return html.unescape(re.sub(r"\s+", " ", match.group(1))).strip(" -:")
    text = read_text(build.text_path)
    for line in text.splitlines()[:80]:
        clean = line.strip()
        if clean and not clean.lower().startswith(("network working group", "request for comments", "rfc", "category", "updates", "obsoletes")):
            if len(clean) > 8:
                return clean
    return f"RFC {build.meta.num}"


def infer_tags(title: str) -> tuple[str, ...]:
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


def derived_meta(num: int, build: RFCBuild) -> RFCMeta:
    title = extract_title(build)
    tags = infer_tags(title)
    return RFCMeta(
        num,
        title,
        f"Pulled in through the RFC update chain; review '{title}' to understand protocol changes that may affect detection, parsing, or investigation context.",
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
    svg = render_header_layout_svg(fields)
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


def page(title: str, content: str, extra_head: str = "") -> str:
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>{html.escape(title)}</title>
  <link rel=\"stylesheet\" href=\"{extra_head}assets/style.css\">
</head>
<body>
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
<div id="map-overlay" class="map-overlay">
  <div class="map-header">
    <div class="eyebrow">Interactive RFC Graph</div>
    <div style="display:flex; gap:10px;">
      <button id="close-map" class="reader-btn">Exit Map (Esc)</button>
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
        <button id="open-map" class="reader-btn" style="border-color:var(--pink); color:var(--pink);">Protocol Map</button>
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
            f"""<a class=\"{card_class}\" href=\"rfc/{slug(meta)}\" data-search=\"{html.escape(search)}\" data-tags=\"{html.escape(' '.join(meta.tags))}\">
  <span class=\"num\">RFC {meta.num} · {status}</span>
  <h2>{html.escape(meta.title)}</h2>
  <p>{html.escape(meta.relevance)}</p>
  <div class=\"tags\">{tags}</div>
  <span class=\"open\">Read chapter</span>
</a>"""
        )

    index_content = f"""
<script src=\"assets/d3.min.js\"></script>
{study_overlay}
{map_overlay}
<script>window.FLASHCARDS = {flashcards};</script>
<header class=\"hero shell\">
  <div class=\"eyebrow\">Curated protocol intelligence</div>
  <h1>RFCs for network threat hunting.</h1>
  <p><strong>{len(builds)} specifications</strong> covering transport, routing, monitoring, security, application-layer behavior, and two-hop update-chain context. Built as a fully local dark-mode reference library with no runtime network dependencies.</p>
</header>
<div class=\"toolbar\"><div class=\"shell\"><div class=\"toolbar-row\"><label class=\"searchbox\"><span>⌕</span><input id=\"q\" autocomplete=\"off\" placeholder=\"Filter by RFC number, title, tag, or keyword...\"></label><div id=\"count\" class=\"view-count\"></div></div><div class=\"filters\">{''.join(filters)}</div></div></div>
<main class=\"shell\">
  <section class=\"stats\">{stats}</section>
  <section class=\"grid\">{''.join(cards)}</section>
  <p class=\"empty\">No matching RFCs. Try a protocol name, tag, or RFC number.</p>
</main>
<footer><div class=\"shell\">Generated locally from rfc-editor.org sources. Open an RFC card to read the cached HTML source or styled plaintext fallback.</div></footer>
<script src=\"assets/index.js\"></script>
"""
    (SITE_DIR / "index.html").write_text(page("RFC Threat Hunting Library", index_content), encoding="utf-8")

    for build in builds:
        meta = build.meta
        tags = "".join(f"<span class=\"tag tag-{html.escape(tag)}\">{html.escape(tag)}</span>" for tag in meta.tags)
        if build.html_ok and build.html_path:
            body = localize_rfc_links(extract_body(read_text(build.html_path)), local_nums)
        elif build.text_ok and build.text_path:
            linked_text = link_plain_metadata_refs(html.escape(read_text(build.text_path)), local_nums)
            body = f"<pre>{linked_text}</pre>"
        else:
            body = "<pre>RFC source could not be fetched.</pre>"
        header_reference = render_header_reference_panel(meta.num)
        threat_indicators = render_threat_indicators(meta.num)
        content = f"""
<script src=\"../assets/d3.min.js\"></script>
<div class=\"progress\"></div>
{study_overlay}
<script>window.FLASHCARDS = {flashcards};</script>
<main class=\"doc-layout\">
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
  <section class=\"reader-grid\"><article class=\"doc-body\">{body}</article><aside class=\"toc-panel\">{threat_indicators}{header_reference}<h2>On this RFC</h2><div id=\"toc-links\"></div></aside></section>
</main>
<script src=\"../assets/doc.js\"></script>
"""
        (SITE_DIR / "rfc" / slug(meta)).write_text(page(f"RFC {meta.num}: {meta.title}", content, "../"), encoding="utf-8")


def plain_to_xhtml(text: str) -> str:
    return f"<pre>{html.escape(text)}</pre>"


def html_to_epub_xhtml(raw: str) -> str:
    body = extract_body(raw)
    body = re.sub(r"<br\s*>", "<br />", body, flags=re.I)
    body = re.sub(r"<hr\s*>", "<hr />", body, flags=re.I)
    return body


def chapter_content(build: RFCBuild, local_nums: set[int], include_category: bool = False) -> str:
    meta = build.meta
    if build.html_ok and build.html_path:
        source = localize_rfc_links(html_to_epub_xhtml(read_text(build.html_path)), local_nums, local_ext=".xhtml")
    elif build.text_ok and build.text_path:
        linked_text = link_plain_metadata_refs(html.escape(read_text(build.text_path)), local_nums, local_ext=".xhtml")
        source = f"<pre>{linked_text}</pre>"
    else:
        source = "<p>RFC source could not be fetched.</p>"
    category = f"<p><strong>Categories:</strong> {html.escape(', '.join(meta.tags))}</p>" if include_category else ""
    return f"""<h1>RFC {meta.num}: {html.escape(meta.title)}</h1>
<aside><p><strong>Threat hunting relevance:</strong> {html.escape(meta.relevance)}</p>{category}</aside>
{source}
"""


def add_epub_css(book: epub.EpubBook) -> epub.EpubItem:
    css = """
body { font-family: Georgia, serif; line-height: 1.62; color: #111827; }
h1 { color: #0f172a; font-size: 1.85em; line-height: 1.08; border-bottom: 2px solid #dbeafe; padding-bottom: .35em; }
h2, h3 { color: #172554; margin-top: 1.4em; }
aside { border-left: 5px solid #2563eb; background: #eef5ff; padding: .8em 1em; margin: 1em 0 1.25em; border-radius: .35em; }
pre { white-space: pre-wrap; font-family: ui-monospace, Consolas, monospace; font-size: .82em; line-height: 1.45; background: #f8fafc; border: 1px solid #e2e8f0; padding: .8em; }
a { color: #1d4ed8; }
a.rfc-local { color: #047857; font-weight: bold; }
a.rfc-external { color: #b45309; font-weight: bold; }
.kicker { color: #2563eb; font-family: sans-serif; font-size: .8em; font-weight: bold; letter-spacing: .12em; text-transform: uppercase; }
.title-page { margin-top: 18%; text-align: center; }
.title-page h1 { border: 0; font-size: 2.4em; }
.title-page p { color: #475569; }
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


def write_complete_epub(builds: list[RFCBuild]) -> None:
    book = make_book("RFC Threat Hunting Collection - Complete", "rfc-threat-hunting-complete")
    intro = make_intro(book, "RFC Threat Hunting Collection", "A complete single-volume protocol field library.")
    chapters = []
    local_nums = {build.meta.num for build in builds}
    for build in builds:
        meta = build.meta
        chapter = epub.EpubHtml(title=f"RFC {meta.num}: {meta.title}", file_name=f"rfc{meta.num}.xhtml", lang="en")
        chapter.content = chapter_content(build, local_nums, include_category=True)
        chapter.add_item(book.get_item_with_id("style_nav"))
        book.add_item(chapter)
        chapters.append(chapter)
    book.toc = (intro, *chapters)
    book.spine = ["nav", intro, *chapters]
    book.add_item(epub.EpubNcx())
    book.add_item(epub.EpubNav())
    epub.write_epub(str(EPUB_DIR / "rfc-threat-hunting-complete.epub"), book)


def write_category_epub(builds: list[RFCBuild]) -> None:
    book = make_book("RFC Threat Hunting Collection - By Category", "rfc-threat-hunting-by-category")
    intro = make_intro(book, "RFC Threat Hunting By Category", "The same RFCs grouped by analyst workflow: application, monitoring, routing, security, and transport.")
    spine: list[object] = ["nav", intro]
    toc = [intro]
    local_nums = {build.meta.num for build in builds}
    by_num = {build.meta.num: build for build in builds}
    for tag in sorted(TAG_DESCRIPTIONS):
        intro = epub.EpubHtml(title=tag.title(), file_name=f"category-{tag}.xhtml", lang="en")
        intro.content = f"<h1>{html.escape(tag.title())}</h1><p>{html.escape(TAG_DESCRIPTIONS[tag])}</p>"
        intro.add_item(book.get_item_with_id("style_nav"))
        book.add_item(intro)
        spine.append(intro)
        category_chapters = []
        for build in builds:
            meta = build.meta
            if tag not in meta.tags:
                continue
            chapter = epub.EpubHtml(title=f"RFC {meta.num}: {meta.title}", file_name=f"{tag}-rfc{meta.num}.xhtml", lang="en")
            chapter.content = chapter_content(build, local_nums, include_category=True)
            chapter.add_item(book.get_item_with_id("style_nav"))
            book.add_item(chapter)
            category_chapters.append(chapter)
            spine.append(chapter)
        toc.append((epub.Section(tag.title()), tuple(category_chapters)))
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
