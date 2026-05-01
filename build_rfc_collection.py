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


STUDY_TRACKS: tuple[dict[str, object], ...] = (
    {
        "id": "foundation",
        "eyebrow": "Sprint 1",
        "title": "Packet Skeleton Crew",
        "summary": "Start with the headers every other protocol has to live inside. Once these feel familiar, the rest of the library stops looking like packet-shaped tax law.",
        "rfcs": (768, 791, 792, 793, 826),
    },
    {
        "id": "naming",
        "eyebrow": "Sprint 2",
        "title": "Boot, Name, Find",
        "summary": "Learn how hosts get addresses, resolve names, and discover services. This is the part where infrastructure either behaves politely or becomes a haunted forest of TXT records.",
        "rfcs": (1035, 1123, 2131, 2782),
    },
    {
        "id": "routing",
        "eyebrow": "Sprint 3",
        "title": "Routes, Lies, and Routers",
        "summary": "Move from local path logic to internet-scale route drama. Ideal for hunters who enjoy phrases like 'that ASN absolutely should not be there.'",
        "rfcs": (1122, 2328, 2460, 4271),
    },
    {
        "id": "security",
        "eyebrow": "Sprint 4",
        "title": "Tunnels and Trust Issues",
        "summary": "Focus on IPsec architecture and ESP so encrypted traffic stops being a mysterious blob and starts becoming something you can reason about.",
        "rfcs": (4301, 4303),
    },
    {
        "id": "app",
        "eyebrow": "Sprint 5",
        "title": "Web and Mail Drama Desk",
        "summary": "HTTP and SMTP are where user intent, parser ambiguity, and attacker creativity all meet for lunch and make your day worse.",
        "rfcs": (2616, 5321, 7230, 7540),
    },
    {
        "id": "telemetry",
        "eyebrow": "Sprint 6",
        "title": "Logs, Flows, and Receipts",
        "summary": "Close with the telemetry RFCs so your protocol knowledge turns into evidence instead of vibes. This is the 'show me the packets and the flow records' phase.",
        "rfcs": (3954, 7011),
    },
)


SCIENCE_NOTES: tuple[dict[str, str], ...] = (
    {
        "title": "Spacing beats cramming for long-term retention",
        "summary": "Distributed practice reliably improves later memory compared with massed review, so the plan uses short repeat visits instead of one heroic weekend binge.",
        "url": "https://doi.org/10.1037/0033-2909.132.3.354",
        "source": "Cepeda et al. (2006)",
    },
    {
        "title": "Retrieval practice outperforms passive restudy",
        "summary": "Low-stakes recall and quizzing help learning stick better than rereading, which is why each session ends with a brief memory dump and due-card review.",
        "url": "https://doi.org/10.3102/0034654316689306",
        "source": "Adesope et al. (2017)",
    },
    {
        "title": "Classroom quizzing boosts learning, especially with feedback",
        "summary": "Practice tests improve achievement across levels and formats, and feedback makes the payoff bigger, so the site leans on repeated review rather than one-and-done reading.",
        "url": "https://doi.org/10.1037/bul0000309",
        "source": "Yang et al. (2021)",
    },
    {
        "title": "Motivation improves when autonomy and relevance are supported",
        "summary": "Learners persist more when they have choice, a manageable path, and a clear reason to care. That is why the library now offers tracks instead of a giant undifferentiated RFC buffet.",
        "url": "https://doi.org/10.1016/j.lmot.2024.102015",
        "source": "Wang et al. (2024)",
    },
    {
        "title": "Interest-triggering reading interventions work best",
        "summary": "Reading motivation improves most when content feels interesting and meaningful, so each sprint is framed like a hunting mission rather than mandatory vegetables.",
        "url": "https://doi.org/10.1007/s10648-023-09719-3",
        "source": "de Nooijer et al. (2024)",
    },
    {
        "title": "If-then plans make starting more likely",
        "summary": "Specific implementation intentions help translate good intentions into action, so the homepage includes a tiny cue-and-response pact you can save locally.",
        "url": "https://doi.org/10.1016/S0065-2601(06)38002-1",
        "source": "Gollwitzer & Sheeran (2006)",
    },
)


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
    792: {
        "title": "RFC 792 ICMP Message Header",
        "note": "ICMP control messages expose reachability, reconnaissance, covert-channel, redirect, and denial-of-service behavior that often precedes or accompanies attacks.",
        "fields": [
            ("Type", 8, "Message class (e.g., Echo, Unreachable); unexpected type distribution reveals scans, floods, tunnels, or route manipulation."),
            ("Code", 8, "Type-specific reason; impossible or rare type/code pairings identify malformed tools, policy bypass, or covert signaling."),
            ("Checksum", 16, "Message integrity; invalid values can be offload artifacts, corruption, or deliberately crafted traffic."),
            ("Identifier", 16, "Used to match request/reply pairs; high entropy or reused IDs can indicate tunneling tools or spoofing."),
            ("Sequence Number", 16, "Monotonic bursts, gaps, or encoded patterns help detect ping sweeps and covert payload channels."),
            ("Gateway Address", 32, "Redirect gateway; unexpected values can reveal route injection or man-in-the-middle attempts."),
            ("Original IP Header", 32, "Quoted packet in errors; MUST be inspected to find spoofed or reconnaissance-induced errors."),
            ("Original Data", 32, "First 64 bits of original payload; for TCP/UDP, this includes ports - critical for correlating errors to flows."),
        ],
    },
    793: {
        "title": "RFC 793 TCP Header",
        "note": "TCP fields drive flow reconstruction, scan detection, and session validation; ICMP errors quoting TCP headers are high-signal for reconnaissance.",
        "fields": [
            ("Source Port", 16, "Client or service port; suspicious reuse or odd pairings can reveal scans or spoofing."),
            ("Destination Port", 16, "Target service; hunt for unauthorized services, fan-out scans, or policy bypass."),
            ("Sequence Number", 32, "Byte-stream position; repeated or out-of-window values may indicate injection or spoofing."),
            ("Acknowledgment Number", 32, "Next expected byte; impossible ACKs reveal scans, desync, or spoofed packets."),
            ("Data Offset", 4, "Header length; large values mean options, while invalid small values are malformed."),
            ("Reserved", 6, "Should be zero; non-zero reserved bits often indicate crafted or evasive traffic."),
            ("TCP Flags", 6, "SYN/ACK/RST/FIN combinations; watch for illegal flag combos, floods, and RST injection."),
            ("Window", 16, "Advertised receive window; zero-window abuse or odd scaling can stand out."),
            ("Checksum", 16, "Integrity check; invalid values can be offload artifacts or crafted packet evidence."),
            ("Urgent Pointer", 16, "Only meaningful with URG; unexpected use can indicate evasion or legacy attacks."),
            ("Options/Padding", 32, "MSS, SACK, timestamps; odd combinations can fingerprint tools or evasions."),
        ],
    },
    826: {
        "title": "RFC 826 ARP over Ethernet Frame",
        "note": "ARP binds protocol addresses to MACs; this layout turns prose into fields hunters can scan for spoofing and poisoning.",
        "fields": [
            ("Hardware Type", 16, "Ethernet should be 1; unexpected values are high-signal for crafted traffic."),
            ("Protocol Type", 16, "IPv4 should be 0x0800; unusual protocols may indicate legacy or suspicious use."),
            ("HLEN", 8, "Hardware address length; Ethernet should be 6 bytes."),
            ("PLEN", 8, "Protocol address length; IPv4 should be 4 bytes."),
            ("Operation", 16, "Request=1, Reply=2; rare opcodes or byte-order mistakes are hunt-worthy."),
            ("Sender MAC", 48, "Compare with L2 source to catch forged ARP payloads or bridge oddities."),
            ("Sender IP", 32, "Conflicts or protected gateway IPs mapped to new MACs are critical poisoning signals."),
            ("Target MAC", 48, "Blank/zero in requests is normal; odd target MACs reveal crafted or proxy behavior."),
            ("Target IP", 32, "Repeated sweeps or gateway targeting can expose reconnaissance."),
        ],
    },
    1035: {
        "title": "RFC 1035 DNS Message Header",
        "note": "DNS header bits summarize query intent and response state used in tunneling and abuse hunts.",
        "fields": [
            ("ID", 16, "Transaction ID; repeated or predictable IDs can indicate spoofing or cache-poisoning."),
            ("QR", 1, "Query/response bit; responses without queries are highly suspicious."),
            ("Opcode", 4, "Operation code; non-standard opcodes (non-zero) are rare and high-signal."),
            ("AA", 1, "Authoritative answer; unexpected authority can indicate rogue infrastructure."),
            ("TC", 1, "Truncation flag; frequent truncation can force TCP fallback or indicate oversized abuse."),
            ("RD", 1, "Recursion desired; unexpected recursion from restricted networks can show resolver misuse."),
            ("RA", 1, "Recursion available; rogue or exposed recursive resolvers often reveal themselves here."),
            ("Z", 3, "Reserved bits; non-zero values are abnormal except negotiated extensions."),
            ("RCODE", 4, "Response code; spikes in NXDOMAIN or SERVFAIL can reveal DGA or probing."),
            ("QDCOUNT", 16, "Question count; values other than one are uncommon in standard queries."),
            ("ANCOUNT", 16, "Answer count; unusual cardinality can indicate amplification or fast-flux."),
            ("NSCOUNT", 16, "Authority count; unexpected delegations can expose suspicious infrastructure."),
            ("ARCOUNT", 16, "Additional count; EDNS and oversized additional data are useful abuse indicators."),
        ],
    },
    2131: {
        "title": "RFC 2131 DHCP Message Header",
        "note": "DHCP fields identify clients, servers, and relay paths during rogue-DHCP investigations.",
        "fields": [
            ("op", 8, "Message op code; direction mismatches can reveal spoofing or relay issues."),
            ("htype", 8, "Hardware type; unexpected values on Ethernet can indicate crafted clients."),
            ("hlen", 8, "Hardware address length; invalid lengths indicate malformed traffic."),
            ("hops", 8, "Relay hop count; high values suggest relay loops or unusual topology."),
            ("xid", 32, "Transaction ID; collisions or mismatches help spot spoofed offers."),
            ("secs", 16, "Elapsed seconds; high values can signal client distress."),
            ("flags", 16, "Broadcast flag; abnormal reserved bit use may indicate crafted clients."),
            ("ciaddr", 32, "Client IP; unexpected preconfigured values can reveal conflicts."),
            ("yiaddr", 32, "Your/client IP; watch unauthorized ranges or duplicate offers."),
            ("siaddr", 32, "Next server; unexpected boot servers can indicate rogue provisioning."),
            ("giaddr", 32, "Relay agent; unexpected relays may show rogue infrastructure."),
            ("chaddr", 128, "Client hardware address; mismatches with L2 source indicate spoofing."),
        ],
    },
    2328: {
        "title": "RFC 2328 OSPFv2 Packet Header",
        "note": "OSPF headers reveal adjacency abuse, area mismatches, authentication failures, and unexpected routing speakers.",
        "fields": [
            ("Version", 8, "Should be 2; mismatches indicate malformed or wrong-protocol traffic."),
            ("Type", 8, "Hello, DB Description, LS Request, LS Update, or LS Ack; unusual bursts can show adjacency attacks."),
            ("Packet Length", 16, "Full OSPF packet length; mismatches suggest malformed packets or capture corruption."),
            ("Router ID", 32, "Originating router identity; duplicate IDs indicate spoofing."),
            ("Area ID", 32, "OSPF area; wrong-area packets are high-signal for rogue routers."),
            ("Checksum", 16, "OSPF packet integrity; invalid checksums indicate corruption or crafted traffic."),
            ("AuType", 16, "Authentication type; none or unexpected auth mode can expose insecure adjacencies."),
            ("Authentication", 64, "Authentication data; failures can reveal adjacency hijack attempts."),
        ],
    },
    2460: {
        "title": "RFC 2460 IPv6 Header & Extension Chain",
        "note": "IPv6 fixed headers plus extension chains expose tunneling, routing, and evasion patterns.",
        "fields": [
            ("Version", 4, "Should be 6; other values indicate malformed traffic or parser confusion."),
            ("Traffic Class", 8, "QoS markings; unusual values can indicate tunneling or covert marking."),
            ("Flow Label", 20, "Flow identifier; inconsistent labels can fingerprint hosts or tools."),
            ("Payload Length", 16, "Length after fixed header; zero jumbo payloads deserve scrutiny."),
            ("Next Header", 8, "Extension header pointer; long or unknown chains can bypass filters."),
            ("Hop Limit", 8, "IPv6 TTL; unusually low or inconsistent values suggest spoofing or probing."),
            ("Source Address", 128, "Origin IPv6; link-local or spoofed sources in wrong zones are suspicious."),
            ("Destination Address", 128, "Target IPv6; unexpected multicast or link-local destinations aid hunting."),
        ],
    },
    4271: {
        "title": "RFC 4271 BGP Update Attributes",
        "note": "BGP UPDATE attributes are central to route-leak, hijack, and suspicious peering investigations.",
        "fields": [
            ("Attr Flags", 8, "Optional/Transitive bits; illegal combinations can propagate bad state."),
            ("Attr Type", 8, "ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF, COMMUNITY; core hunting pivots."),
            ("ORIGIN", 8, "IGP/EGP/INCOMPLETE; unexpected changes can signal leaks or hijacks."),
            ("AS_PATH", 32, "Primary vector for hijacking; watch impossible paths and prepending abuse."),
            ("NEXT_HOP", 32, "Reachability; unexpected next-hops can reveal redirection or blackholes."),
            ("COMMUNITY", 32, "Policy tags; blackhole or provider-specific tags can alter propagation."),
        ],
    },
    4303: {
        "title": "RFC 4303 ESP Header & Trailer",
        "note": "ESP hides payloads, so SPI, sequence behavior, and policy context become the hunting surface.",
        "fields": [
            ("SPI", 32, "Security Parameters Index; unknown or reused SPIs can indicate rogue tunnels."),
            ("Sequence", 32, "Anti-replay value; resets or gaps suggest replay attempts or failover confusion."),
            ("Payload", 32, "Encrypted data; size and timing are key signals when contents are opaque."),
            ("Padding", 32, "Alignment bytes; unusual patterns can fingerprint implementations."),
            ("Pad Length", 8, "Number of padding bytes; impossible values indicate malformed ESP."),
            ("Next Header", 8, "Protected inner protocol; visible after decryption; useful for policy validation."),
            ("ICV", 32, "Integrity Check Value; failures indicate tampering or wrong keys."),
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
    792: [
        {"name": "ICMP Tunneling", "normal": "Echo payloads are short diagnostics with predictable size and content.", "malicious": "High-entropy or oversized echo payloads move command data or exfiltration through ICMP.", "sev": "high"},
        {"name": "Ping Floods", "normal": "Low-rate echo requests with matching replies for diagnostics.", "malicious": "Sustained high-volume echo requests, spoofed sources, or one-way floods cause denial of service.", "sev": "high"},
        {"name": "Redirect Abuse", "normal": "ICMP redirects are rare and generally constrained to local gateway correction.", "malicious": "Unexpected redirect messages point hosts at attacker-controlled gateways for traffic interception.", "sev": "high"},
        {"name": "Reconnaissance Error Bursts", "normal": "Occasional unreachable or time-exceeded messages during real failures.", "malicious": "Bursts of destination-unreachable or time-exceeded messages reveal sweeps, traceroute mapping, or spoofed probing.", "sev": "medium"},
    ],
    793: [
        {"name": "Illegal Flag Combinations", "normal": "Valid state transitions (SYN, SYN-ACK, etc).", "malicious": "NULL, Xmas, or SYN-FIN scans; flags that shouldn't exist together.", "sev": "high"},
        {"name": "SYN Flood Patterns", "normal": "Balanced SYN and ACK packets.", "malicious": "Massive burst of SYNs without corresponding ACKs from many IPs.", "sev": "high"},
        {"name": "RST Injection", "normal": "RST sent on connection close or error.", "malicious": "Unsolicited RSTs designed to kill active legitimate sessions.", "sev": "medium"},
        {"name": "Window Size Anomalies", "normal": "Dynamic window scaling based on congestion.", "malicious": "Stuck at tiny values or zero-window probes to hang servers.", "sev": "medium"},
        {"name": "Urgent Pointer Abuse", "normal": "Rarely used in modern protocols.", "malicious": "Non-zero urgent pointer in data-less packets to trigger parser bugs.", "sev": "low"},
    ],
    826: [
        {"name": "ARP Poisoning", "normal": "Addresses are mapped to correct MACs and remain stable.", "malicious": "Gratuitous ARP or spoofed replies mapping gateway IPs to attacker MACs.", "sev": "high"},
        {"name": "MAC Flooding", "normal": "CAM table contains legitimate local entries.", "malicious": "Thousands of fake MACs fill switches, forcing fail-open hub behavior.", "sev": "medium"},
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
        {"name": "Tunneled 6-in-4", "normal": "Native IPv6 paths and explicitly approved tunnels.", "malicious": "Protocol 41, 6to4, or Teredo traffic appears where IPv6 tunneling is not authorized.", "sev": "medium"},
        {"name": "Fragment Header Evasion", "normal": "Fragmentation is uncommon on well-behaved IPv6 paths.", "malicious": "Atomic, tiny, excessive, or evasive fragments attempt to bypass ACLs and IDS reassembly.", "sev": "high"},
        {"name": "Unexpected ICMPv6", "normal": "Essential ND and error messages.", "malicious": "Flood of Redirects or RA to perform MitM or DoS.", "sev": "high"},
    ],
    4271: [
        {"name": "AS_PATH Anomalies", "normal": "Paths consistent with historical peering.", "malicious": "Impossibly short or circular paths; unauthorized AS inclusion.", "sev": "high"},
        {"name": "Prefix Hijacking Patterns", "normal": "Origins match authorized IRR/RPKI records.", "malicious": "Unauthorized AS announcing a more-specific or new prefix.", "sev": "high"},
        {"name": "Unusual COMMUNITY Values", "normal": "Used for standard traffic engineering.", "malicious": "Proprietary or 'blackhole' communities used to redirect traffic.", "sev": "medium"},
        {"name": "Route Leaks", "normal": "Routes stay within intended peering boundaries.", "malicious": "Propagating private peering routes to the global internet.", "sev": "medium"},
    ],
    4301: [
        {"name": "Policy Bypass", "normal": "Traffic matching protected selectors is carried through expected IPsec policy.", "malicious": "Sensitive flows appear in cleartext or outside the expected tunnel policy.", "sev": "high"},
        {"name": "Unexpected Security Associations", "normal": "SAs are negotiated between approved peers and lifetimes.", "malicious": "New or stale SAs appear for unknown peers, wrong subnets, or suspicious lifetimes.", "sev": "high"},
        {"name": "Selector Drift", "normal": "Protected source, destination, and protocol selectors match documented policy.", "malicious": "Broad selectors or changed peer identities expose unintended traffic to tunnel or bypass paths.", "sev": "medium"},
    ],
    4303: [
        {"name": "Unexpected ESP", "normal": "ESP appears only between approved VPN/IPsec peers.", "malicious": "ESP from unknown endpoints or unexpected networks can hide unauthorized tunnels.", "sev": "high"},
        {"name": "Replay or Sequence Abuse", "normal": "Sequence numbers advance without repeats inside an SA.", "malicious": "Repeated or sharply regressing sequence numbers suggest replay, failover confusion, or crafted traffic.", "sev": "medium"},
        {"name": "Integrity Failures", "normal": "ESP authentication checks pass for active SAs.", "malicious": "ICV failures indicate tampering, wrong keys, corruption, or probing of IPsec endpoints.", "sev": "high"},
        {"name": "Policy Bypass", "normal": "Inner protected traffic matches IPsec policy after decryption.", "malicious": "Unexpected inner protocols or subnets reveal overly broad tunnel policy or abuse.", "sev": "high"},
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

DETECTION_QUESTIONS: dict[int, list[str]] = {
    768: ["Are UDP length values consistent with observed payload sizes?", "Are amplification-prone services receiving small requests and sending large responses?", "Are source or destination ports impossible, zero, or outside expected service policy?"],
    791: ["Are fragmented IPv4 packets tiny, overlapping, or excessive for the application?", "Do TTL values shift unexpectedly for the same source or path?", "Are IP options or source-routing fields present where policy forbids them?"],
    792: ["Are ICMP type/code pairs valid for the observed flow and destination?", "Are echo payloads unusually large, high-entropy, or persistent enough to indicate tunneling?", "Are redirect messages changing host gateways outside approved router paths?", "Are ICMP errors clustering around scans or impossible source addresses?"],
    793: ["Are TCP flag combinations valid for the expected connection state?", "Are SYNs balanced by ACKs or are they forming a flood pattern?", "Are RSTs arriving out of window or from unexpected network positions?", "Are ICMP errors quoting TCP headers pointing to valid internal ports?"],
    826: ["Do ARP sender hardware addresses match Ethernet source addresses?", "Are protected gateway IPs suddenly mapped to new MAC addresses?", "Are gratuitous ARP replies or target sweeps appearing outside normal operations?"],
    1035: ["Are DNS labels unusually long, random, or high entropy?", "Are query counts, response codes, or additional sections outside normal resolver behavior?", "Are TXT or NULL-like payloads being used for data movement?"],
    2131: ["Are DHCP offers coming from only authorized server addresses?", "Are many distinct client hardware addresses exhausting leases rapidly?", "Are router, DNS, or boot-server options changing unexpectedly?"],
    2328: ["Are OSPF packets coming from approved router IDs and areas?", "Are authentication modes and checksums valid for each adjacency?", "Are LSA floods or max-age events happening outside topology changes?"],
    2460: ["Are IPv6 extension headers chained deeper than policy allows?", "Is protocol 41, 6to4, or Teredo traffic present where tunneling is not approved?", "Are fragment headers used for tiny, atomic, or evasive fragments?"],
    3954: ["Are NetFlow exporters limited to approved devices?", "Do flow records show many tiny one-way flows consistent with scanning?", "Are template IDs rotating faster than expected?"],
    4271: ["Do advertised prefixes match authorized origins and expected peers?", "Are AS_PATH values impossibly short, looping, private, or suddenly changed?", "Are communities or next-hop attributes redirecting traffic unexpectedly?"],
    4301: ["Do protected selectors match documented IPsec policy?", "Is sensitive traffic ever observed outside the required tunnel?", "Are new SAs appearing for unknown peers or broad subnets?"],
    4303: ["Is ESP limited to approved IPsec peers and expected SPI values?", "Do ESP sequence numbers repeat or regress within a security association?", "Do decrypted inner protocols match tunnel policy?"],
    5321: ["Are SMTP command sequences valid and expected for the sender role?", "Are null senders, relay attempts, or EHLO anomalies increasing?", "Are 4xx/5xx replies clustering around authentication or delivery abuse?"],
    7011: ["Are IPFIX exporters limited to approved devices?", "Are templates stable and consistent with known telemetry profiles?", "Do unidirectional flows or fan-out patterns indicate scanning or DDoS?"],
    7230: ["Are HTTP message headers malformed, duplicated, or conflicting?", "Are proxy-routing headers changing the intended destination?", "Are request smuggling indicators present across front-end and back-end parsing?"],
    7540: ["Are HTTP/2 frame sequences valid for stream state?", "Are SETTINGS, RST_STREAM, or GOAWAY frames spiking abnormally?", "Are multiplexed streams hiding fan-out or unusual request timing?"],
}

for _rfc_num, _questions in DETECTION_QUESTIONS.items():
    if _rfc_num in HEADER_REFERENCES:
        HEADER_REFERENCES[_rfc_num]["detection_questions"] = _questions

KNOWN_RFC_TAG_GROUPS: dict[str, set[int]] = {
    "application": {1035, 1123, 2131, 2616, 2782, 5321, 7230, 7540, 821, 882, 883, 973, 974, 1034, 1101, 1183, 1348, 1349, 1455, 1637, 1788, 1825, 1827, 1869, 1876, 1995, 1996, 2052, 2065, 2068, 2136, 2137, 2145, 2181, 2308, 2401, 2406, 2474, 2535, 2617, 2673, 2817, 2818, 2821, 2845, 2931, 3007, 3008, 3090, 3225, 3226, 3363, 3364, 3396, 3597, 3645, 3655, 3757, 3845, 4033, 4034, 4035, 4305, 4343, 4361, 4470, 5336, 5395, 5452, 5785, 5864, 5890, 5936, 5966, 6014, 6195, 6266, 6335, 6585, 6840, 6842, 6891, 6895, 6944, 7231, 7232, 7233, 7234, 7235, 7474, 7504, 7595, 7615, 7694, 7766, 8020, 8198, 8436, 8482, 8490, 8499, 8553, 8615, 8740, 8767, 8945, 9103, 9110, 9111, 9112, 9113, 9210, 9499, 9520, 9619, 9824, 9905},
    "routing": {791, 792, 826, 1122, 2460, 2328, 4271, 974, 1583, 1654, 1771, 1788, 1827, 1883, 2178, 2406, 2474, 2481, 2873, 3168, 3226, 3363, 3364, 3697, 4724, 4884, 4893, 5065, 5095, 5101, 5227, 5336, 5462, 5494, 5709, 5722, 5871, 6286, 6425, 6426, 6437, 6472, 6549, 6564, 6608, 6633, 6793, 6829, 6845, 6860, 6864, 6918, 6935, 6946, 7045, 7112, 7474, 7506, 7606, 7705, 8029, 8042, 8200, 8212, 8538, 8611, 8654, 9072, 9355, 9454, 9570, 9601, 9673, 9687, 9774},
    "monitoring": {1035, 2131, 2616, 2782, 3954, 5321, 7011, 7230, 3697, 5101, 6437},
    "security": {791, 792, 826, 1122, 2460, 4271, 4301, 4303, 1455, 1825, 1827, 1948, 2065, 2137, 2401, 2406, 2535, 2617, 2845, 3007, 3008, 3090, 3225, 3226, 3645, 3655, 3757, 3845, 4033, 4034, 4035, 4305, 4470, 4635, 5709, 5961, 6014, 6335, 6528, 6840, 6944, 7235, 7474, 7615, 7619, 8198, 8482, 8945, 9824, 9905},
    "transport": {768, 793, 1122, 4303, 7540, 879, 1827, 2406, 2873, 2988, 4305, 5961, 5966, 6093, 6298, 6335, 6429, 6691, 6935, 7766, 9210, 9293, 9768, 9868},
    "update-chain": {821, 879, 882, 883, 950, 973, 974, 1011, 1034, 1101, 1183, 1348, 1349, 1455, 1531, 1541, 1583, 1637, 1654, 1771, 1788, 1825, 1827, 1869, 1876, 1883, 1948, 1982, 1995, 1996, 2052, 2065, 2068, 2136, 2137, 2145, 2178, 2181, 2205, 2308, 2401, 2406, 2474, 2481, 2535, 2617, 2673, 2817, 2818, 2821, 2845, 2873, 2931, 2988, 3007, 3008, 3090, 3168, 3225, 3226, 3260, 3363, 3364, 3396, 3425, 3445, 3597, 3645, 3655, 3658, 3697, 3755, 3757, 3845, 3864, 4033, 4034, 4035, 4305, 4343, 4361, 4379, 4470, 4635, 4724, 4884, 4893, 5065, 5095, 5101, 5227, 5336, 5395, 5452, 5462, 5494, 5709, 5722, 5785, 5864, 5871, 5884, 5890, 5936, 5961, 5966, 6014, 6040, 6093, 6195, 6266, 6286, 6298, 6335, 6424, 6425, 6426, 6429, 6437, 6472, 6528, 6549, 6564, 6585, 6604, 6608, 6633, 6691, 6793, 6829, 6840, 6842, 6845, 6860, 6864, 6891, 6895, 6918, 6935, 6944, 6946, 7045, 7112, 7231, 7232, 7233, 7234, 7235, 7474, 7504, 7506, 7537, 7538, 7595, 7606, 7607, 7615, 7619, 7694, 7705, 7726, 7743, 7766, 8020, 8029, 8042, 8198, 8200, 8212, 8311, 8335, 8436, 8482, 8490, 8499, 8538, 8553, 8611, 8615, 8654, 8740, 8767, 8945, 9041, 9072, 9077, 9103, 9110, 9111, 9112, 9113, 9210, 9293, 9355, 9454, 9499, 9520, 9570, 9601, 9619, 9673, 9687, 9768, 9774, 9824, 9868, 9905},
}

KNOWN_RFC_TAGS: dict[int, tuple[str, ...]] = {
    num: tuple(tag for tag in TAG_DESCRIPTIONS if num in KNOWN_RFC_TAG_GROUPS[tag])
    for num in set().union(*KNOWN_RFC_TAG_GROUPS.values())
}

RELATION_RE = re.compile(r"\b(Updated by|Obsoletes|Obsoleted by):(?P<body>.*?)(?=<br\s*/?>|\n|</span>|$)", re.I | re.S)
RFC_NUM_RE = re.compile(r"\b(?:RFCs?\s*)?(\d{3,5})\b", re.I)


SITE_CSS = r"""

:root {
  color-scheme: dark;
  --bg: #070912;
  --panel: #0e1424;
  --panel2: #111a2d;
  --panel3: #152035;
  --text: #eef5ff;
  --text2: #d8e6fa;
  --muted: #9fb0c9;
  --muted2: #7a88a1;
  --line: rgba(255,255,255,.11);
  --line2: rgba(255,255,255,.08);
  --cyan: #65e4ff;
  --cyan2: #4dc8ff;
  --violet: #b89cff;
  --violet2: #a388ff;
  --pink: #ff70b8;
  --pink2: #ff5aa0;
  --green: #7dffa8;
  --green2: #5eff8c;
  --amber: #ffd36a;
  --amber2: #ffc748;
  --red: #ff6b8b;
  --glass: rgba(14,20,36,.65);
  --glass2: rgba(14,20,36,.85);
}

* { box-sizing: border-box; }
*::before, *::after { box-sizing: border-box; }

html {
  scroll-behavior: smooth;
  text-rendering: optimizeLegibility;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

body {
  margin: 0;
  min-height: 100vh;
  background: 
    radial-gradient(circle at 12% -10%, rgba(101,228,255,.22), transparent 32rem),
    radial-gradient(circle at 88% 8%, rgba(184,156,255,.2), transparent 31rem),
    radial-gradient(circle at 50% 90%, rgba(255,112,184,.12), transparent 38rem),
    linear-gradient(135deg, #050711 0%, #09111e 48%, #100b1f 100%);
  color: var(--text);
  font: 16px/1.6 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

body:before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background-image: 
    linear-gradient(rgba(255,255,255,.025) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.025) 1px, transparent 1px);
  background-size: 44px 44px;
  mask-image: radial-gradient(circle at top, black, transparent 75%);
}

/* Subtle animated background stars */
body:after {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background: transparent;
}

/* Animation keyframes */
@keyframes float {
  0%, 100% { transform: translateY(0) translateX(0); opacity: 0.4; }
  50% { transform: translateY(-20px) translateX(10px); opacity: 0.7; }
}

@keyframes pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.8; transform: scale(1.02); }
}

@keyframes glow {
  0%, 100% { box-shadow: 0 0 20px rgba(101,228,255,0.3); }
  50% { box-shadow: 0 0 40px rgba(101,228,255,0.5), 0 0 60px rgba(184,156,255,0.3); }
}

@keyframes shimmer {
  0% { background-position: -200% 0; }
  100% { background-position: 200% 0; }
}

@keyframes slideUp {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

a {
  color: inherit;
  text-decoration: none;
  transition: color 0.2s ease;
}

a:hover {
  color: var(--cyan);
}

/* Shell container */
.shell {
  width: min(1180px, calc(100% - 34px));
  margin: 0 auto;
}

/* ==================== HERO SECTION ==================== */
.hero {
  padding: 80px 0 48px;
  text-align: center;
  animation: slideUp 0.6s ease-out;
}

.eyebrow {
  display: inline-block;
  color: var(--cyan);
  text-transform: uppercase;
  letter-spacing: .22em;
  font-size: .78rem;
  font-weight: 800;
  margin-bottom: 16px;
  padding: 6px 14px;
  border-radius: 999px;
  background: rgba(101,228,255,.1);
  border: 1px solid rgba(101,228,255,.2);
  animation: pulse 4s ease-in-out infinite;
}

h1 {
  margin: 12px 0 16px;
  font-size: clamp(2.7rem, 8vw, 6.8rem);
  line-height: .86;
  letter-spacing: -.08em;
  max-width: 960px;
  margin-left: auto;
  margin-right: auto;
  background: linear-gradient(135deg, var(--text), var(--cyan), var(--violet));
  background-clip: text;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-fill-color: transparent;
}

.hero p {
  max-width: 780px;
  color: var(--text2);
  font-size: 1.12rem;
  line-height: 1.7;
  margin: 0 auto;
  font-weight: 400;
}

.hero strong {
  color: var(--text);
  font-weight: 600;
}

/* ==================== TOOLBAR ==================== */
.toolbar {
  position: sticky;
  top: 0;
  z-index: 5;
  padding: 18px 0;
  backdrop-filter: blur(24px) saturate(1.2);
  -webkit-backdrop-filter: blur(24px) saturate(1.2);
  background: linear-gradient(to bottom, 
    rgba(7,9,18,.95), 
    rgba(7,9,18,.82));
  border-bottom: 1px solid var(--line);
  transition: all 0.3s ease;
}

.toolbar.scrolled {
  padding: 14px 0;
  box-shadow: 0 8px 40px rgba(0,0,0,0.4);
}

.toolbar-row {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 16px;
  align-items: center;
}

.searchbox {
  display: flex;
  gap: 14px;
  align-items: center;
  padding: 14px 18px 14px 18px;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--glass2);
  box-shadow: 
    inset 0 1px 0 rgba(255,255,255,.08),
    0 8px 32px rgba(0,0,0,.25);
  transition: all 0.25s ease;
  backdrop-filter: blur(12px);
}

.searchbox:focus-within {
  border-color: rgba(101,228,255,.5);
  box-shadow: 
    0 0 0 3px rgba(101,228,255,.15),
    inset 0 1px 0 rgba(255,255,255,.08),
    0 8px 40px rgba(0,0,0,.35);
}

.searchbox span {
  color: var(--cyan);
  font-weight: 900;
  font-size: 1.05rem;
  transition: color 0.2s ease;
}

.searchbox input {
  flex: 1;
  min-width: 240px;
}

.searchbox input::placeholder {
  color: #7a88a1;
}

.searchbox input:focus {
  outline: none;
}

.view-count {
  color: var(--muted);
  font-weight: 800;
  white-space: nowrap;
  font-size: 0.9rem;
  padding: 10px 14px;
  border-radius: 999px;
  background: var(--glass);
  border: 1px solid var(--line2);
}

.filters {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 14px;
}

/* ==================== BUTTONS ==================== */
button.filter,
button.reader-btn {
  cursor: pointer;
  color: #eaf3ff;
  border: 1px solid rgba(255,255,255,.14);
  background: var(--glass);
  border-radius: 999px;
  padding: 8px 14px;
  font: inherit;
  font-size: .86rem;
  font-weight: 900;
  letter-spacing: 0.02em;
  transition: all 0.22s cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
  overflow: hidden;
}

button.filter::before,
button.reader-btn::before {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(180deg, 
    rgba(255,255,255,.1) 0%,
    rgba(255,255,255,.03) 100%);
  opacity: 0;
  transition: opacity 0.22s ease;
}

button.filter:hover,
button.reader-btn:hover {
  transform: translateY(-2px);
  border-color: rgba(101,228,255,.6);
  background: rgba(101,228,255,.2);
  box-shadow: 0 8px 24px rgba(101,228,255,.25);
}

button.filter:hover::before,
button.reader-btn:hover::before {
  opacity: 1;
}

button.filter.active {
  transform: translateY(-1px);
  border-color: rgba(101,228,255,.7);
  background: rgba(101,228,255,.25);
  color: var(--text);
}

/* Special button styles for accent buttons */
button.reader-btn.style-pink {
  border-color: rgba(255,112,184,.4);
  background: rgba(255,112,184,.12);
  color: var(--pink);
}

button.reader-btn.style-pink:hover {
  border-color: var(--pink);
  background: rgba(255,112,184,.25);
  color: var(--pink2);
}

button.reader-btn.style-cyan {
  border-color: rgba(101,228,255,.4);
  background: rgba(101,228,255,.12);
  color: var(--cyan);
}

button.reader-btn.style-cyan:hover {
  border-color: var(--cyan);
  background: rgba(101,228,255,.25);
}

input {
  width: 100%;
  border: 0;
  outline: 0;
  background: transparent;
  color: var(--text);
  font: inherit;
  font-size: 1rem;
}

input::placeholder {
  color: #7a88a1;
}

input:focus {
  outline: none;
}

/* ==================== STATS ==================== */
.stats {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 14px;
  margin: 28px 0 36px;
}

.stat {
  border: 1px solid var(--line);
  border-radius: 24px;
  padding: 20px;
  background: linear-gradient(145deg, 
    rgba(255,255,255,.09), 
    rgba(255,255,255,.04));
  min-height: 116px;
  transition: all 0.25s ease;
  position: relative;
  overflow: hidden;
}

.stat::before {
  content: "";
  position: absolute;
  top: -50%;
  left: -50%;
  width: 200%;
  height: 200%;
  background: radial-gradient(circle, 
    rgba(101,228,255,.1) 0%, 
    transparent 70%);
  opacity: 0;
  transition: opacity 0.3s ease;
}

.stat:hover {
  transform: translateY(-4px);
  border-color: rgba(101,228,255,.4);
  box-shadow: 0 12px 40px rgba(101,228,255,.2);
}

.stat:hover::before {
  opacity: 0.3;
}

.stat b {
  display: block;
  font-size: 1.55rem;
  line-height: 1.2;
  font-weight: 900;
  letter-spacing: -0.02em;
  background: linear-gradient(135deg, var(--cyan), var(--violet));
  background-clip: text;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-fill-color: transparent;
}

.stat span {
  color: var(--muted2);
  font-size: .86rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-top: 8px;
  display: block;
}
/* ==================== CARDS GRID ==================== */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(310px, 1fr));
  gap: 20px;
  padding: 12px 0 80px;
}

.card {
  position: relative;
  overflow: hidden;
  min-height: 252px;
  padding: 24px;
  border-radius: 30px;
  background: linear-gradient(145deg, 
    rgba(19,28,48,.98), 
    rgba(11,16,30,.92));
  border: 1px solid var(--line);
  box-shadow: 
    0 12px 48px rgba(0,0,0,.45),
    inset 0 1px 0 rgba(255,255,255,.04);
  transition: 
    transform 0.3s cubic-bezier(0.4, 0, 0.2, 1),
    border-color 0.25s ease,
    box-shadow 0.3s ease;
}

.card::before {
  content: "";
  position: absolute;
  inset: -1px;
  opacity: 0.65;
  background: 
    radial-gradient(circle at top right, 
      rgba(101,228,255,.24), 
      transparent 48%),
    radial-gradient(circle at bottom left, 
      rgba(255,112,184,.18), 
      transparent 45%);
  pointer-events: none;
  transition: opacity 0.3s ease;
}

.card::after {
  content: "";
  position: absolute;
  inset: -2px;
  border-radius: 32px;
  border: 1px solid transparent;
  background: linear-gradient(145deg, 
    rgba(255,255,255,.12), 
    rgba(255,255,255,.04));
  opacity: 0;
  transition: opacity 0.25s ease, border-color 0.25s ease;
  z-index: -1;
}

.card:hover {
  transform: translateY(-6px) scale(1.01);
  border-color: rgba(101,228,255,.55);
  box-shadow: 
    0 20px 70px rgba(0,0,0,.55),
    0 8px 32px rgba(101,228,255,.15);
}

.card:hover::before {
  opacity: 0.85;
}

.card:hover::after {
  opacity: 1;
  border-color: rgba(101,228,255,.2);
}

.card.chain {
  border-color: rgba(255,211,106,.38);
}

.card.chain::before {
  background: 
    radial-gradient(circle at top right, 
      rgba(255,211,106,.28), 
      transparent 48%),
    radial-gradient(circle at bottom left, 
      rgba(184,156,255,.22), 
      transparent 45%);
}

.card.chain:hover {
  border-color: rgba(255,211,106,.6);
  box-shadow: 
    0 20px 70px rgba(0,0,0,.55),
    0 8px 32px rgba(255,211,106,.25);
}

.card > * {
  position: relative;
}

/* Card animation on load */
@keyframes cardIn {
  from {
    opacity: 0;
    transform: translateY(30px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.card {
  animation: cardIn 0.4s ease-out backwards;
}

.card:nth-child(1) { animation-delay: 0.02s; }
.card:nth-child(2) { animation-delay: 0.04s; }
.card:nth-child(3) { animation-delay: 0.06s; }
.card:nth-child(4) { animation-delay: 0.08s; }
.card:nth-child(5) { animation-delay: 0.1s; }
.card:nth-child(6) { animation-delay: 0.12s; }
.card:nth-child(7) { animation-delay: 0.14s; }
.card:nth-child(8) { animation-delay: 0.16s; }
.card:nth-child(9) { animation-delay: 0.18s; }
.card:nth-child(10) { animation-delay: 0.2s; }
.card:nth-child(11) { animation-delay: 0.22s; }
.card:nth-child(12) { animation-delay: 0.24s; }

.num {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  color: var(--cyan);
  font-weight: 900;
  letter-spacing: 0.08em;
  font-size: 0.95rem;
  transition: color 0.2s ease;
}

.card:hover .num {
  color: var(--cyan2);
}

.num::before {
  content: "";
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--green);
  box-shadow: 
    0 0 20px var(--green),
    0 0 40px var(--green2);
  animation: pulse 3s ease-in-out infinite;
}

.card h2 {
  margin: 16px 0 12px;
  font-size: 1.38rem;
  line-height: 1.14;
  letter-spacing: -0.04em;
  color: var(--text);
  transition: color 0.2s ease;
}

.card:hover h2 {
  color: var(--text2);
}

.card p {
  margin: 0 0 22px;
  color: var(--muted2);
  line-height: 1.55;
  font-size: 0.95rem;
}

.tags, .meta-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.tag {
  color: #e2efff;
  border: 1px solid rgba(255,255,255,.16);
  background: rgba(255,255,255,.06);
  border-radius: 999px;
  padding: 6px 11px;
  font-size: .76rem;
  font-weight: 800;
  letter-spacing: 0.04em;
  transition: all 0.2s ease;
  backdrop-filter: blur(10px);
}

.tag:hover {
  border-color: rgba(101,228,255,.4);
  background: rgba(101,228,255,.12);
  color: var(--cyan);
  transform: translateY(-1px);
}

.tag-routing {
  border-color: rgba(184,156,255,.3);
  background: rgba(184,156,255,.1);
  color: rgba(184,156,255,.9);
}

.tag-transport {
  border-color: rgba(255,211,106,.3);
  background: rgba(255,211,106,.1);
  color: rgba(255,211,106,.9);
}

.tag-application {
  border-color: rgba(255,112,184,.3);
  background: rgba(255,112,184,.1);
  color: rgba(255,112,184,.9);
}

.tag-security {
  border-color: rgba(125,255,168,.3);
  background: rgba(125,255,168,.1);
  color: rgba(125,255,168,.9);
}

.tag-monitoring {
  border-color: rgba(101,228,255,.3);
  background: rgba(101,228,255,.1);
  color: rgba(101,228,255,.9);
}

.tag-update-chain {
  color: #1b1300;
  border-color: rgba(255,211,106,.8);
  background: linear-gradient(135deg, var(--amber), #ff9f6a);
  font-weight: 900;
  box-shadow: 0 4px 16px rgba(255,211,106,.25);
}

.open {
  display: inline-flex;
  margin-top: 22px;
  color: var(--text);
  font-weight: 900;
  font-size: 0.95rem;
  letter-spacing: 0.04em;
  transition: all 0.2s ease;
}

.open::after {
  content: "→";
  margin-left: 9px;
  color: var(--pink);
  transition: transform 0.2s ease, color 0.2s ease;
}

.open:hover {
  color: var(--cyan);
}

.open:hover::after {
  transform: translateX(4px);
  color: var(--pink2);
}

.empty {
  display: none;
  color: var(--muted);
  padding: 48px 0 90px;
  text-align: center;
  font-size: 1.1rem;
}

.empty.display {
  display: block;
  animation: slideUp 0.4s ease-out;
}
.toplink {
  color: var(--cyan);
  font-weight: 900;
  font-size: 0.9rem;
  transition: all 0.2s ease;
}

.toplink:hover {
  color: var(--cyan2);
  text-shadow: 0 0 12px rgba(101,228,255,.5);
}

.progress {
  position: fixed;
  top: 0;
  left: 0;
  height: 4px;
  width: 0;
  z-index: 20;
  background: linear-gradient(90deg, var(--cyan), var(--violet), var(--pink), var(--amber));
  background-size: 400% 100%;
  box-shadow: 0 0 28px rgba(101,228,255,.7);
  transition: width 0.3s ease;
  animation: shimmer 8s linear infinite;
}

/* ==================== DOC LAYOUT ==================== */
.doc-layout {
  width: min(1160px, calc(100% - 32px));
  margin: 0 auto;
  padding: 40px 0 90px;
  animation: slideUp 0.5s ease-out;
}

.reader-tools {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  justify-content: space-between;
  margin: 20px 0;
  padding: 14px 16px;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--glass2);
  backdrop-filter: blur(16px);
  box-shadow: 0 8px 32px rgba(0,0,0,.2);
}

.reader-tools .group {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.doc-hero {
  margin: 24px 0 28px;
  padding: 32px 36px;
  border: 1px solid var(--line);
  border-radius: 32px;
  background: linear-gradient(145deg, 
    rgba(19,28,48,.98), 
    rgba(12,17,31,.92));
  box-shadow: 
    0 12px 50px rgba(0,0,0,.45),
    inset 0 1px 0 rgba(255,255,255,.04);
  position: relative;
  overflow: hidden;
}

.doc-hero::before {
  content: "";
  position: absolute;
  inset: -1px;
  opacity: 0.5;
  background: 
    radial-gradient(circle at top right, 
      rgba(101,228,255,.18), 
      transparent 45%),
    radial-gradient(circle at bottom left, 
      rgba(184,156,255,.14), 
      transparent 42%);
  pointer-events: none;
}

.doc-hero h1 {
  font-size: clamp(2.1rem, 5.5vw, 5rem);
  max-width: none;
  line-height: 1.05;
  letter-spacing: -0.06em;
  margin: 0 0 12px;
  color: var(--text);
  background: linear-gradient(135deg, var(--text), var(--cyan));
  background-clip: text;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-fill-color: transparent;
}

.doc-hero .eyebrow {
  margin-bottom: 12px;
  animation: none;
  background: rgba(101,228,255,.08);
  border: 1px solid rgba(101,228,255,.2);
}

.note {
  margin: 20px 0 0;
  padding: 18px 22px;
  border-left: 4px solid var(--cyan);
  border-radius: 16px;
  color: #e2efff;
  background: rgba(101,228,255,.07);
  box-shadow: 0 4px 20px rgba(101,228,255,.1);
  font-size: 0.98rem;
  line-height: 1.6;
}

.reader-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 280px;
  gap: 20px;
  align-items: start;
}

.doc-body {
  position: relative;
  isolation: isolate;
  overflow: hidden;
  padding: 38px 40px;
  border: 1px solid var(--line);
  border-radius: 30px;
  background: rgba(6,9,17,.88);
  box-shadow: 
    0 28px 100px rgba(0,0,0,.45),
    inset 0 1px 0 rgba(255,255,255,.03);
}

.doc-body.focus {
  max-width: 840px;
  margin: 0 auto;
  font-size: 1.06rem;
  line-height: 1.8;
}

.doc-body::before {
  content: "";
  position: absolute;
  inset: -1px;
  z-index: 0;
  opacity: 0.4;
  background: 
    radial-gradient(circle at top right, 
      rgba(101,228,255,.12), 
      transparent 45%),
    radial-gradient(circle at bottom left, 
      rgba(184,156,255,.1), 
      transparent 42%);
  pointer-events: none;
  border-radius: 31px;
}

.doc-body > * {
  position: relative;
  z-index: 1;
}

.doc-body pre {
  white-space: pre-wrap;
  color: #e2efff;
  font: .93rem/1.72 "IBM Plex Mono", "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  background: transparent;
  padding: 0;
  border-radius: 0;
  margin: 0;
  overflow-x: auto;
}

.doc-body.comfy pre,
.doc-body.comfy {
  font-size: 1.08rem;
  line-height: 1.8;
}

.doc-body table {
  max-width: 100%;
  border-collapse: collapse;
  margin: 18px 0;
}

.doc-body table th,
.doc-body table td {
  padding: 10px 14px;
  border: 1px solid var(--line2);
}

.doc-body table th {
  background: var(--glass);
  color: var(--cyan);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 0.85rem;
}

.doc-body, .doc-body p, .doc-body td, .doc-body li, .doc-body pre {
  color: #e2efff;
  line-height: 1.7;
}

.doc-body a {
  color: var(--cyan);
  text-decoration: underline;
  text-underline-offset: 3px;
  transition: all 0.2s ease;
}

.doc-body a:hover {
  color: var(--cyan2);
  text-shadow: 0 0 12px rgba(101,228,255,.4);
}

.doc-body a[href^="#section-"] {
  display: inline-block;
  padding: 0.02rem 0.44rem;
  border-radius: 999px;
  background: rgba(101,228,255,.1);
  box-shadow: inset 0 0 0 1px rgba(101,228,255,.18);
  text-decoration: none;
  font-weight: 800;
}

.doc-body a[href^="#page-"] {
  color: var(--muted);
  text-decoration-color: rgba(255,255,255,.24);
}

.doc-body a.rfc-local {
  color: var(--green);
  font-weight: 900;
  text-decoration-color: rgba(125,255,168,.55);
}

.doc-body a.rfc-external {
  color: var(--amber);
  font-weight: 900;
  text-decoration-style: dotted;
}

.doc-body a.rfc-local:after {
  content: " local";
  font-size: .68em;
  color: var(--green);
  text-transform: uppercase;
  margin-left: .25em;
}

.doc-body a.rfc-external:after {
  content: " external";
  font-size: .68em;
  color: var(--amber);
  text-transform: uppercase;
  margin-left: .25em;
}

.doc-body h1, .doc-body h2, .doc-body h3 {
  color: var(--text);
  margin: 24px 0 16px;
  line-height: 1.2;
}

.doc-body h1 {
  font-size: clamp(2rem, 4vw, 3.2rem);
  border-bottom: 2px solid var(--line);
  padding-bottom: 12px;
}

.doc-body h2 {
  font-size: clamp(1.5rem, 3vw, 2.1rem);
  border-bottom: 1px solid var(--line2);
  padding-bottom: 8px;
  color: var(--cyan);
}

.doc-body h3 {
  font-size: 1.35rem;
  color: var(--violet);
}

.source-banner {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(220px, .95fr);
  gap: 18px;
  margin: 0 0 22px;
  padding: 22px 24px;
  border: 1px solid rgba(101,228,255,.2);
  border-radius: 24px;
  background:
    linear-gradient(145deg, rgba(101,228,255,.11), rgba(184,156,255,.08)),
    rgba(8,12,24,.82);
  box-shadow:
    0 16px 48px rgba(0,0,0,.28),
    inset 0 1px 0 rgba(255,255,255,.05);
}

.source-kicker {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
  color: var(--cyan);
  font-size: .78rem;
  font-weight: 900;
  letter-spacing: .16em;
  text-transform: uppercase;
}

.source-kicker::before {
  content: "";
  width: 10px;
  height: 10px;
  border-radius: 999px;
  background: linear-gradient(135deg, var(--cyan), var(--violet));
  box-shadow: 0 0 14px rgba(101,228,255,.45);
}

.source-banner strong {
  display: block;
  margin-bottom: 8px;
  font-size: 1.22rem;
  line-height: 1.2;
  color: var(--text);
}

.source-banner p {
  margin: 0;
  color: var(--text2);
  max-width: 60ch;
}

.source-meta {
  display: flex;
  flex-wrap: wrap;
  align-content: start;
  gap: 10px;
  justify-content: flex-end;
}

.source-chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-height: 42px;
  padding: 10px 14px;
  border: 1px solid rgba(255,255,255,.1);
  border-radius: 999px;
  background: rgba(7,10,19,.56);
  color: var(--text2);
  font-size: .85rem;
  font-weight: 700;
  letter-spacing: .02em;
}

.source-chip::before {
  content: "";
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: var(--amber);
  box-shadow: 0 0 12px rgba(255,211,106,.35);
}

.rfc-source-shell {
  display: grid;
  gap: 18px;
}

.rfc-page {
  position: relative;
  padding: 20px 22px 24px;
  border: 1px solid rgba(255,255,255,.09);
  border-radius: 26px;
  background:
    linear-gradient(180deg, rgba(255,255,255,.035), rgba(255,255,255,.015)),
    rgba(10,14,28,.82);
  box-shadow:
    0 18px 46px rgba(0,0,0,.28),
    inset 0 1px 0 rgba(255,255,255,.04);
  overflow: hidden;
}

.rfc-page::before {
  content: "";
  position: absolute;
  inset: 0 auto 0 0;
  width: 4px;
  background: linear-gradient(180deg, var(--cyan), var(--violet));
  opacity: .9;
}

.rfc-page.is-cover {
  background:
    radial-gradient(circle at top right, rgba(101,228,255,.08), transparent 34%),
    linear-gradient(180deg, rgba(255,255,255,.045), rgba(255,255,255,.018)),
    rgba(10,14,28,.9);
}

.rfc-page.is-contents::after {
  content: "jump links live here";
  position: absolute;
  top: 18px;
  right: 18px;
  padding: 7px 10px;
  border-radius: 999px;
  border: 1px solid rgba(101,228,255,.18);
  background: rgba(101,228,255,.08);
  color: var(--cyan);
  font-size: .7rem;
  font-weight: 900;
  letter-spacing: .14em;
  text-transform: uppercase;
}

.rfc-page-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin: 0 0 14px;
}

.rfc-page-label {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,.1);
  background: rgba(7,11,20,.62);
  color: var(--text2);
  font-size: .74rem;
  font-weight: 900;
  letter-spacing: .16em;
  text-transform: uppercase;
}

.rfc-page-label::before {
  content: "";
  width: 7px;
  height: 7px;
  border-radius: 999px;
  background: var(--green);
  box-shadow: 0 0 10px rgba(125,255,168,.38);
}

.rfc-page-meta {
  margin: 0 0 18px;
  padding: 14px 16px;
  border: 1px solid rgba(255,255,255,.08);
  border-radius: 18px;
  background: rgba(255,255,255,.03);
  color: var(--muted);
  font-size: .82rem;
  line-height: 1.75;
}

.rfc-page-meta a:not([href]) {
  color: var(--muted);
  text-decoration: none;
  border-bottom: 1px dashed rgba(255,255,255,.12);
}

.rfc-page-meta a[href] {
  font-weight: 700;
}

.rfc-page pre + pre,
.rfc-page details + pre,
.rfc-page pre + details,
.rfc-page details + details {
  margin-top: 16px;
}

.rfc-page .header-reference-panel,
.rfc-page .arp-flowchart-panel,
.rfc-page .modern-ascii-diagram {
  margin-top: 20px;
  margin-bottom: 20px;
}

.modern-ascii-diagram {
  position: relative;
  padding: 22px;
  border: 1px solid rgba(101,228,255,.26);
  border-radius: 26px;
  background:
    radial-gradient(circle at 16% 12%, rgba(101,228,255,.22), transparent 32%),
    radial-gradient(circle at 86% 18%, rgba(184,156,255,.2), transparent 34%),
    linear-gradient(145deg, rgba(9,15,32,.96), rgba(5,8,18,.94));
  box-shadow:
    0 22px 70px rgba(0,0,0,.34),
    inset 0 1px 0 rgba(255,255,255,.08),
    0 0 42px rgba(101,228,255,.08);
  overflow: hidden;
}

.modern-ascii-diagram::before {
  content: "";
  position: absolute;
  inset: -40% -20% auto;
  height: 120px;
  background: linear-gradient(90deg, transparent, rgba(101,228,255,.2), transparent);
  transform: rotate(-8deg);
}

.modern-diagram-kicker {
  position: relative;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 14px;
  color: var(--cyan);
  font-size: .76rem;
  font-weight: 900;
  letter-spacing: .16em;
  text-transform: uppercase;
}

.modern-diagram-kicker::before {
  content: "";
  width: 9px;
  height: 9px;
  border-radius: 999px;
  background: linear-gradient(135deg, var(--cyan), var(--violet));
  box-shadow: 0 0 16px rgba(101,228,255,.55);
}

.modern-diagram-grid {
  position: relative;
  display: grid;
  gap: 9px;
}

.modern-diagram-row {
  display: grid;
  grid-template-columns: repeat(var(--cell-count, 1), minmax(0, 1fr));
  gap: 9px;
}

.modern-diagram-cell {
  min-height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 10px 12px;
  border: 1px solid rgba(255,255,255,.12);
  border-radius: 15px;
  background:
    linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.03)),
    rgba(101,228,255,.06);
  color: #f6fbff;
  text-align: center;
  font: 800 .82rem/1.25 Inter, system-ui, sans-serif;
  box-shadow: inset 0 1px 0 rgba(255,255,255,.08);
}

.modern-diagram-row:nth-child(5n+1) .modern-diagram-cell { border-color: rgba(101,228,255,.28); }
.modern-diagram-row:nth-child(5n+2) .modern-diagram-cell { border-color: rgba(184,156,255,.26); }
.modern-diagram-row:nth-child(5n+3) .modern-diagram-cell { border-color: rgba(125,255,168,.24); }
.modern-diagram-row:nth-child(5n+4) .modern-diagram-cell { border-color: rgba(255,211,106,.24); }
.modern-diagram-row:nth-child(5n+5) .modern-diagram-cell { border-color: rgba(255,111,145,.24); }

.modern-diagram-fallback {
  white-space: pre-wrap;
  color: #e2efff;
  font: .86rem/1.55 "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
}

.doc-body.focus .rfc-source-shell {
  max-width: 78ch;
  margin: 0 auto;
}

.doc-body.comfy .rfc-page {
  padding: 22px 24px 28px;
}

.doc-body.comfy .rfc-page pre {
  font-size: .99rem;
  line-height: 1.82;
}

.toc-panel {
  position: sticky;
  top: 102px;
  max-height: calc(100vh - 140px);
  overflow: auto;
  padding: 20px;
  border: 1px solid var(--line);
  border-radius: 26px;
  background: var(--glass2);
  backdrop-filter: blur(20px);
  box-shadow: 0 12px 40px rgba(0,0,0,.3);
}

.toc-panel::-webkit-scrollbar {
  width: 6px;
}

.toc-panel::-webkit-scrollbar-track {
  background: transparent;
  border-radius: 3px;
}

.toc-panel::-webkit-scrollbar-thumb {
  background: rgba(101,228,255,.3);
  border-radius: 3px;
}

.toc-panel::-webkit-scrollbar-thumb:hover {
  background: rgba(101,228,255,.5);
}

.toc-panel h2 {
  margin: 16px 0 14px;
  font-size: .92rem;
  color: var(--cyan);
  text-transform: uppercase;
  letter-spacing: .16em;
  font-weight: 800;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--line2);
}

.toc-panel a {
  display: block;
  color: var(--muted2);
  font-size: .88rem;
  line-height: 1.35;
  padding: 9px 8px;
  border-bottom: 1px solid var(--line2);
  border-radius: 8px;
  transition: all 0.2s ease;
}

.toc-panel a:hover {
  color: var(--cyan);
  background: rgba(101,228,255,.08);
  padding-left: 14px;
  border-left: 3px solid var(--cyan);
}

.toc-panel .muted {
  color: var(--muted);
  font-size: .86rem;
  padding: 12px 8px;
  font-style: italic;
}
.header-reference-panel,
.detection-questions-panel {
  margin: 0 0 20px;
  border: 1px solid rgba(101,228,255,.28);
  border-radius: 22px;
  background: linear-gradient(145deg, 
    rgba(101,228,255,.12), 
    rgba(255,112,184,.06));
  overflow: hidden;
  box-shadow: 0 8px 32px rgba(101,228,255,.15);
}

.doc-body > .header-reference-panel.inline-header-reference {
  margin: 28px 0 34px;
  box-shadow: 
    0 20px 60px rgba(0,0,0,.35),
    inset 0 1px 0 rgba(255,255,255,.06);
  animation: slideUp 0.5s ease-out;
}

.doc-body > .header-reference-panel.inline-header-reference summary strong {
  font-size: 1.1rem;
  color: var(--text);
}

.doc-body > .header-reference-panel.inline-header-reference .header-note {
  font-size: .94rem;
  color: var(--text2);
}

.doc-body > .header-reference-panel.inline-header-reference .header-diagram-wrap {
  margin-bottom: 20px;
  padding: 14px;
  border-radius: 16px;
  background: rgba(5,7,17,.4);
}

.doc-body > .header-reference-panel.inline-header-reference .header-field-table {
  font-size: .84rem;
  line-height: 1.45;
}
.arp-flowchart-panel {
  position: relative;
  margin: 32px 0 38px;
  padding: 28px;
  border: 1px solid rgba(101,228,255,.35);
  border-radius: 30px;
  overflow: hidden;
  background: 
    radial-gradient(circle at 10% 0%, 
      rgba(101,228,255,.26), 
      transparent 35%),
    radial-gradient(circle at 90% 10%, 
      rgba(255,112,184,.22), 
      transparent 36%),
    linear-gradient(145deg, 
      rgba(11,18,33,.99), 
      rgba(17,22,44,.94));
  box-shadow: 
    0 28px 90px rgba(0,0,0,.42),
    inset 0 1px 0 rgba(255,255,255,.08);
  animation: slideUp 0.6s ease-out;
}

.arp-flowchart-panel:before {
  content: "";
  position: absolute;
  inset: -40%;
  background: conic-gradient(from 120deg, 
    transparent, 
    rgba(101,228,255,.12), 
    transparent, 
    rgba(255,112,184,.1), 
    transparent);
  animation: arpGlow 16s linear infinite;
  opacity: 0.8;
}

.arp-flowchart-panel > * {
  position: relative;
  z-index: 1;
}

.arp-flowchart-kicker {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  padding: 7px 12px;
  border: 1px solid rgba(101,228,255,.32);
  border-radius: 999px;
  color: var(--cyan);
  background: rgba(101,228,255,.1);
  font-size: .72rem;
  font-weight: 900;
  letter-spacing: .16em;
  text-transform: uppercase;
  backdrop-filter: blur(10px);
}

.arp-flowchart-panel h2 {
  margin: 16px 0 10px;
  color: var(--text);
  font-size: clamp(1.4rem, 3.2vw, 2.25rem);
  line-height: 1.15;
  letter-spacing: -0.04em;
}

.arp-flowchart-panel .flow-subtitle {
  margin: 0 0 20px;
  color: #d0dfff;
  max-width: 880px;
  line-height: 1.6;
  font-size: 1.02rem;
}
.arp-flow { display:grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 14px; align-items:stretch; }
.flow-node {
  position: relative;
  min-height: 96px;
  padding: 16px;
  border: 1px solid rgba(255,255,255,.16);
  border-radius: 22px;
  background: linear-gradient(145deg, 
    rgba(255,255,255,.09), 
    rgba(255,255,255,.04));
  box-shadow: 
    inset 0 1px 0 rgba(255,255,255,.08),
    0 4px 16px rgba(0,0,0,.2);
  transition: all 0.25s ease;
}

.flow-node:hover {
  transform: translateY(-2px);
  box-shadow: 
    inset 0 1px 0 rgba(255,255,255,.12),
    0 8px 28px rgba(0,0,0,.35);
}

.flow-node strong {
  display: block;
  color: #f8fbff;
  font-size: .98rem;
  line-height: 1.22;
  font-weight: 800;
  margin-bottom: 6px;
}

.flow-node small {
  display: block;
  margin-top: 8px;
  color: #c0d0e8;
  line-height: 1.4;
  font-size: 0.86rem;
}

.flow-node code {
  color: #ffeb88;
  font-weight: 900;
  font-size: 0.9rem;
}

.flow-node.start {
  grid-column: span 12;
  min-height: auto;
  border-color: rgba(125,255,168,.35);
  background: linear-gradient(90deg, 
    rgba(125,255,168,.18), 
    rgba(101,228,255,.12));
  box-shadow: 0 0 24px rgba(125,255,168,.2);
}

.flow-node.decision {
  grid-column: span 4;
  border-color: rgba(101,228,255,.4);
  background: linear-gradient(145deg, 
    rgba(101,228,255,.18), 
    rgba(184,156,255,.1));
}

.flow-node.action {
  grid-column: span 4;
  border-color: rgba(184,156,255,.32);
  background: linear-gradient(145deg, 
    rgba(184,156,255,.12), 
    rgba(255,255,255,.04));
}

.flow-node.merge {
  grid-column: span 8;
  border-color: rgba(255,211,106,.35);
  background: linear-gradient(145deg, 
    rgba(255,211,106,.16), 
    rgba(255,112,184,.09));
}

.flow-node.reply {
  grid-column: span 6;
  border-color: rgba(125,255,168,.38);
  background: linear-gradient(145deg, 
    rgba(125,255,168,.16), 
    rgba(101,228,255,.1));
}

.flow-node.stop {
  grid-column: span 4;
  border-color: rgba(255,112,184,.35);
  background: linear-gradient(145deg, 
    rgba(255,112,184,.2), 
    rgba(255,255,255,.04));
}

.flow-pill {
  display: inline-flex;
  margin-bottom: 10px;
  padding: 5px 10px;
  border-radius: 999px;
  background: rgba(0,0,0,.3);
  color: var(--cyan);
  font-size: .66rem;
  font-weight: 900;
  letter-spacing: .14em;
  text-transform: uppercase;
  backdrop-filter: blur(10px);
}

.flow-node.stop .flow-pill { color: var(--pink); }
.flow-node.reply .flow-pill { color: var(--green); }
.flow-node.merge .flow-pill { color: var(--amber); }

.flow-arrow {
  grid-column: span 12;
  text-align: center;
  color: var(--cyan);
  font-weight: 900;
  letter-spacing: .2em;
  text-transform: uppercase;
  font-size: .72rem;
  opacity: 0.95;
  padding: 8px 0;
}

.flow-branch {
  display: grid;
  grid-column: span 12;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  gap: 16px;
  margin: 4px 0;
}

.flow-branch .yes-line {
  grid-column: span 8;
  padding: 10px 14px;
  border-left: 3px solid rgba(125,255,168,.6);
  color: var(--green);
  font-size: .74rem;
  font-weight: 900;
  text-transform: uppercase;
  letter-spacing: .16em;
  background: rgba(125,255,168,.08);
}

.flow-branch .no-line {
  grid-column: span 4;
  padding: 10px 14px;
  border-left: 3px solid rgba(255,112,184,.6);
  color: var(--pink);
  font-size: .74rem;
  font-weight: 900;
  text-transform: uppercase;
  letter-spacing: .16em;
  background: rgba(255,112,184,.08);
}
@keyframes arpGlow { to { transform: rotate(1turn); } }
.header-reference-panel summary,
.detection-questions-panel summary {
  cursor: pointer;
  list-style: none;
  padding: 16px 18px;
  border-bottom: 1px solid var(--line2);
  transition: background 0.2s ease;
}

.header-reference-panel summary:hover,
.detection-questions-panel summary:hover {
  background: rgba(101,228,255,.08);
}

.header-reference-panel summary::-webkit-details-marker,
.detection-questions-panel summary::-webkit-details-marker {
  display: none;
}

.header-reference-panel summary span,
.detection-questions-panel summary span {
  display: block;
  color: var(--cyan);
  text-transform: uppercase;
  letter-spacing: .16em;
  font-size: .68rem;
  font-weight: 900;
}

.header-reference-panel summary strong,
.detection-questions-panel summary strong {
  display: block;
  margin-top: 6px;
  color: var(--text);
  font-size: 1rem;
  line-height: 1.2;
  font-weight: 700;
}

.header-reference-panel summary:after,
.detection-questions-panel summary:after {
  content: "▾";
  float: right;
  margin-top: -28px;
  color: var(--pink);
  font-weight: 900;
  font-size: 1.1rem;
  transition: transform 0.2s ease, color 0.2s ease;
}

.header-reference-panel[open] summary:after,
.detection-questions-panel[open] summary:after {
  transform: rotate(180deg);
  color: var(--cyan);
}

.header-reference-panel:not([open]) summary,
.detection-questions-panel:not([open]) summary {
  border-bottom: 0;
}

.header-reference-panel:not([open]) summary:after,
.detection-questions-panel:not([open]) summary:after {
  content: "▸";
  color: var(--muted);
}

.header-note {
  margin: 14px 16px;
  color: #e2efff;
  font-size: .88rem;
  line-height: 1.5;
}

.detection-questions-panel ol {
  margin: 14px 18px 18px 36px;
  color: var(--text2);
  font-size: .9rem;
}

.detection-questions-panel li + li {
  margin-top: 8px;
}
.bit-axis {
  margin: 0 16px 8px;
  color: var(--muted2);
  font-size: .74rem;
  font-weight: 900;
  letter-spacing: .1em;
  text-transform: uppercase;
}

.header-diagram-wrap {
  margin: 0 14px 18px;
  overflow-x: auto;
  padding: 14px;
  border: 1px solid rgba(255,255,255,.14);
  border-radius: 18px;
  background: rgba(5,7,17,.65);
  box-shadow: inset 0 8px 24px rgba(0,0,0,.3);
}

.header-bit-layout {
  min-width: 340px;
  width: 100%;
  height: auto;
  display: block;
}

.bit-label {
  fill: #a8b8d4;
  font: 10.5px ui-monospace, SFMono-Regular, Consolas, monospace;
  font-weight: 600;
}

.bit-grid {
  stroke: rgba(255,255,255,.18);
  stroke-width: 1.2;
}

.field-block {
  stroke: rgba(255,255,255,.32);
  stroke-width: 1.2;
}

.field-0 { fill: rgba(101,228,255,.42); }
.field-1 { fill: rgba(184,156,255,.42); }
.field-2 { fill: rgba(255,112,184,.36); }
.field-3 { fill: rgba(125,255,168,.32); }
.field-4 { fill: rgba(255,211,106,.36); }

.field-label {
  fill: #fcfdff;
  font: 9.5px ui-monospace, SFMono-Regular, Consolas, monospace;
  font-weight: 800;
  pointer-events: none;
  text-shadow: 0 2px 4px rgba(0,0,0,.4);
}

.header-field-table {
  width: calc(100% - 28px);
  margin: 0 14px 18px;
  border-collapse: collapse;
  font-size: .78rem;
  line-height: 1.4;
}

.header-field-table th,
.header-field-table td {
  padding: 9px 8px;
  border-top: 1px solid var(--line2);
  vertical-align: top;
}

.header-field-table th {
  color: var(--cyan);
  text-align: left;
  font-size: .72rem;
  text-transform: uppercase;
  letter-spacing: .1em;
  font-weight: 800;
  background: rgba(101,228,255,.06);
  padding: 10px 10px;
}

.header-field-table td:nth-child(2) {
  color: var(--amber);
  font-weight: 900;
  white-space: nowrap;
  font-variant-numeric: tabular-nums;
}

.header-field-table td:nth-child(3) {
  color: var(--text2);
  font-size: 0.88em;
}
footer {
  color: var(--muted2);
  border-top: 1px solid var(--line);
  padding: 32px 0 56px;
  text-align: center;
  font-size: 0.9rem;
}

footer .shell {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}

/* ==================== FLASHCARD STYLES ==================== */
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
  padding: 24px;
  backdrop-filter: blur(20px);
}

.study-overlay::before {
  content: "";
  position: fixed;
  inset: 0;
  background: radial-gradient(circle at center, 
    rgba(7,9,18,0.95), 
    rgba(7,9,18,0.85));
  backdrop-filter: blur(12px);
}

.study-overlay.active {
  display: flex;
  animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.study-header {
  position: absolute;
  top: 24px;
  width: min(840px, 100%);
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: var(--muted2);
  font-size: 0.95rem;
  font-weight: 600;
}

.study-progress-bar {
  position: absolute;
  top: 0;
  left: 0;
  height: 5px;
  background: linear-gradient(90deg, var(--cyan), var(--violet), var(--pink));
  background-size: 200% 100%;
  transition: width 0.3s ease;
  animation: shimmer 10s linear infinite;
  box-shadow: 0 0 28px rgba(101,228,255,.6);
}

.card-container {
  width: min(640px, 100%);
  height: 420px;
  perspective: 1200px;
  cursor: pointer;
}

.flashcard {
  position: relative;
  width: 100%;
  height: 100%;
  text-align: center;
  transition: transform 0.6s cubic-bezier(0.4, 0, 0.2, 1);
  transform-style: preserve-3d;
}

.card-container.flipped .flashcard {
  transform: rotateY(180deg);
}

.card-face {
  position: absolute;
  width: 100%;
  height: 100%;
  backface-visibility: hidden;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 44px;
  border-radius: 34px;
  border: 2px solid var(--line);
  background: var(--panel);
  box-shadow: 
    0 36px 120px rgba(0,0,0,0.6),
    inset 0 2px 0 rgba(255,255,255,.04);
  transition: all 0.3s ease;
}

.card-face:hover {
  box-shadow: 
    0 40px 140px rgba(0,0,0,0.7),
    inset 0 2px 0 rgba(255,255,255,.06);
}

.card-back {
  transform: rotateY(180deg);
  border-color: var(--cyan);
  background: linear-gradient(145deg, 
    rgba(14,20,36,0.98), 
    rgba(11,16,30,0.94));
}

.card-category {
  position: absolute;
  top: 32px;
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.24em;
  color: var(--cyan);
  font-weight: 800;
}

.card-prompt {
  font-size: 1.9rem;
  font-weight: 800;
  line-height: 1.18;
  margin: 24px 0;
  color: var(--text);
}

.card-answer {
  font-size: 1.15rem;
  line-height: 1.65;
  color: var(--text2);
  max-width: 100%;
  overflow-y: auto;
  padding-right: 8px;
}

.card-meta {
  position: absolute;
  bottom: 32px;
  font-size: 0.74rem;
  color: var(--muted2);
  letter-spacing: 0.08em;
}

.study-actions {
  margin-top: 44px;
  display: none;
  gap: 18px;
}

.study-actions.visible {
  display: flex;
  animation: slideUp 0.3s ease-out;
}

.srs-btn {
  padding: 14px 28px;
  border-radius: 999px;
  border: none;
  font-weight: 900;
  cursor: pointer;
  font-size: 1rem;
  transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  letter-spacing: 0.04em;
  box-shadow: 0 8px 24px rgba(0,0,0,0.4);
}

.srs-btn:hover {
  transform: translateY(-3px);
  box-shadow: 0 12px 36px rgba(0,0,0,0.6);
}

.srs-btn:active {
  transform: translateY(-1px);
}

.btn-again {
  background: linear-gradient(145deg, var(--pink), var(--pink2));
  color: var(--bg);
}

.btn-hard {
  background: linear-gradient(145deg, var(--amber), var(--amber2));
  color: var(--bg);
}

.btn-good {
  background: linear-gradient(145deg, var(--cyan), var(--cyan2));
  color: var(--bg);
}

.btn-easy {
  background: linear-gradient(145deg, var(--green), var(--green2));
  color: var(--bg);
}

.study-summary {
  text-align: center;
  display: none;
  padding: 40px 0;
}

.study-summary.active {
  display: block;
  animation: slideUp 0.4s ease-out;
}

.study-summary h1 {
  color: var(--text);
  margin-bottom: 32px;
  font-size: 2.4rem;
  background: linear-gradient(135deg, var(--cyan), var(--violet));
  background-clip: text;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-fill-color: transparent;
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 24px;
  margin: 32px 0 40px;
}

.summary-stat {
  padding: 24px;
  background: var(--panel2);
  border-radius: 24px;
  border: 1px solid var(--line);
  transition: all 0.25s ease;
}

.summary-stat:hover {
  transform: translateY(-4px);
  border-color: rgba(101,228,255,.4);
  box-shadow: 0 12px 40px rgba(101,228,255,.2);
}

.summary-stat b {
  display: block;
  font-size: 2.2rem;
  color: var(--cyan);
  line-height: 1.1;
}

.summary-stat span {
  color: var(--muted2);
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-top: 8px;
  display: block;
}

/* ==================== RESPONSIVE DESIGN ==================== */
@media (max-width: 980px) {
  .reader-grid {
    grid-template-columns: 1fr;
  }
  
  .toc-panel {
    position: relative;
    top: auto;
    max-height: none;
    order: -1;
  }
  
  .stats {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (max-width: 780px) {
  .toolbar-row {
    grid-template-columns: 1fr;
    gap: 14px;
  }
  
  .stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  
  .hero {
    padding-top: 52px;
  }
  
  .doc-body,
  .doc-hero {
    padding: 22px;
    border-radius: 24px;
  }

  .source-banner {
    grid-template-columns: 1fr;
    padding: 18px;
  }

  .source-meta {
    justify-content: flex-start;
  }

  .rfc-page {
    padding: 18px 18px 20px;
    border-radius: 22px;
  }

  .rfc-page.is-contents::after {
    position: static;
    display: inline-flex;
    margin: 0 0 12px;
  }
  
  .reader-tools {
    border-radius: 24px;
    flex-direction: column;
    align-items: stretch;
  }
  
  .reader-tools .group {
    justify-content: center;
  }
  
  .header-field-table {
    font-size: .74rem;
  }
  
  .arp-flowchart-panel {
    padding: 20px;
    border-radius: 24px;
  }
  
  .flow-node,
  .flow-node.start,
  .flow-node.decision,
  .flow-node.action,
  .flow-node.merge,
  .flow-node.reply,
  .flow-node.stop {
    grid-column: span 12;
  }
  
  .summary-grid {
    grid-template-columns: 1fr;
    gap: 16px;
  }
}

@media (max-width: 480px) {
  .hero {
    padding: 50px 0 32px;
  }
  
  h1 {
    font-size: clamp(2rem, 10vw, 4rem);
  }
  
  .searchbox {
    padding: 12px 14px;
  }
  
  .card {
    min-height: 240px;
    padding: 20px;
  }
  
  .grid {
    grid-template-columns: 1fr;
    gap: 16px;
  }
  
  .stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }
  
  .stat {
    min-height: 100px;
    padding: 16px;
  }
  
  .stat b {
    font-size: 1.35rem;
  }
}

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

/* ==================== DESIGN REFRESH: hierarchy, scanning, accessibility ==================== */
:root {
  --focus-ring: rgba(101, 228, 255, .55);
  --surface-strong: rgba(11, 16, 30, .94);
  --surface-soft: rgba(255, 255, 255, .045);
}

::selection { background: rgba(101,228,255,.28); color: var(--text); }

body { text-wrap: pretty; }

.skip-link {
  position: fixed;
  left: 18px;
  top: 14px;
  z-index: 10000;
  transform: translateY(-140%);
  padding: 10px 14px;
  border-radius: 999px;
  color: #04111a;
  background: var(--cyan);
  font-weight: 900;
  box-shadow: 0 16px 40px rgba(0,0,0,.45);
}
.skip-link:focus { transform: translateY(0); }

:where(a, button, input, textarea, summary):focus-visible {
  outline: 3px solid var(--focus-ring);
  outline-offset: 3px;
  box-shadow: 0 0 0 6px rgba(101,228,255,.12);
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.inline-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}
.inline-actions.center { justify-content: center; }

.hero {
  position: relative;
  isolation: isolate;
}
.hero::after {
  content: "";
  display: block;
  width: min(760px, 72vw);
  height: 1px;
  margin: 32px auto 0;
  background: linear-gradient(90deg, transparent, rgba(101,228,255,.52), rgba(255,112,184,.32), transparent);
}
.hero-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 10px;
  margin-top: 26px;
}
.hero-action {
  min-height: 44px;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 10px 15px;
  border: 1px solid rgba(255,255,255,.14);
  border-radius: 999px;
  color: var(--text2);
  background: linear-gradient(145deg, rgba(255,255,255,.085), rgba(255,255,255,.035));
  box-shadow: inset 0 1px 0 rgba(255,255,255,.08), 0 14px 34px rgba(0,0,0,.24);
  font-weight: 850;
  font-size: .9rem;
  transition: transform .18s ease, border-color .18s ease, background .18s ease, color .18s ease;
}
.hero-action:hover {
  transform: translateY(-2px);
  color: var(--text);
  border-color: rgba(101,228,255,.46);
  background: rgba(101,228,255,.11);
}
.hero-action.primary {
  color: #061018;
  border-color: rgba(101,228,255,.72);
  background: linear-gradient(135deg, var(--cyan), var(--violet));
}

.study-plan {
  margin: 26px 0 34px;
  padding: clamp(22px, 3vw, 34px);
  border: 1px solid rgba(101,228,255,.18);
  border-radius: 34px;
  background:
    radial-gradient(circle at top left, rgba(101,228,255,.14), transparent 30%),
    radial-gradient(circle at 85% 12%, rgba(255,112,184,.12), transparent 28%),
    linear-gradient(145deg, rgba(13,20,36,.96), rgba(10,14,28,.92));
  box-shadow:
    0 24px 80px rgba(0,0,0,.34),
    inset 0 1px 0 rgba(255,255,255,.08);
}

.study-plan-intro h2 {
  margin: 10px 0 14px;
  font-size: clamp(2rem, 4vw, 3.3rem);
  line-height: .94;
  letter-spacing: -.05em;
  color: var(--text);
}

.study-plan-intro p {
  max-width: 72ch;
  margin: 0;
  color: var(--text2);
  font-size: 1.02rem;
}

.study-plan-grid,
.study-track-grid {
  display: grid;
  gap: 16px;
  margin-top: 24px;
}

.study-plan-grid {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.study-track-grid {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.study-card,
.study-track {
  position: relative;
  overflow: hidden;
  padding: 22px;
  border: 1px solid rgba(255,255,255,.1);
  border-radius: 26px;
  background: linear-gradient(160deg, rgba(255,255,255,.055), rgba(255,255,255,.02));
  box-shadow: inset 0 1px 0 rgba(255,255,255,.05);
}

.study-card::before,
.study-track::before {
  content: "";
  position: absolute;
  inset: 0 auto auto 0;
  width: 100%;
  height: 1px;
  background: linear-gradient(90deg, rgba(101,228,255,.45), transparent 60%);
}

.study-card h3,
.study-track h3 {
  margin: 8px 0 12px;
  font-size: 1.28rem;
  line-height: 1.1;
  letter-spacing: -.03em;
  color: var(--text);
}

.study-card p,
.study-track p,
.study-active span {
  color: var(--text2);
}

.study-card-kicker,
.study-track-kicker {
  display: inline-flex;
  align-items: center;
  min-height: 28px;
  padding: 0 10px;
  border-radius: 999px;
  border: 1px solid rgba(101,228,255,.22);
  color: var(--cyan);
  background: rgba(101,228,255,.08);
  text-transform: uppercase;
  letter-spacing: .14em;
  font-size: .7rem;
  font-weight: 900;
}

.study-list {
  margin: 0;
  padding-left: 18px;
  color: var(--text2);
}

.study-list li + li {
  margin-top: 10px;
}

.study-aside {
  margin: 14px 0 0;
  color: var(--muted);
  font-size: .92rem;
}

.if-then-form {
  display: grid;
  gap: 14px;
  margin-top: 14px;
}

.if-then-form label {
  display: grid;
  gap: 8px;
}

.if-then-form label span {
  color: var(--text);
  font-size: .9rem;
  font-weight: 700;
}

.if-then-preview {
  min-height: 74px;
  padding: 14px 16px;
  border: 1px dashed rgba(255,255,255,.14);
  border-radius: 18px;
  color: var(--text2);
  background: rgba(6,10,20,.45);
}

.study-status {
  min-height: 1.2em;
  color: var(--green);
  font-size: .9rem;
  font-weight: 700;
}

.study-status-row {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: end;
  gap: 14px;
  margin-top: 24px;
}

.study-active {
  display: grid;
  gap: 5px;
}

.study-active strong {
  color: var(--text);
  font-size: 1.15rem;
}

.study-chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 16px 0 18px;
}

.study-chip {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  padding: 0 11px;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,.1);
  background: rgba(255,255,255,.05);
  color: var(--text2);
  font-size: .84rem;
  font-weight: 700;
}

.study-track-head {
  display: grid;
  gap: 8px;
}

.study-path-btn.active {
  border-color: rgba(101,228,255,.68);
  box-shadow: 0 0 0 3px rgba(101,228,255,.12);
}

.science-list {
  display: grid;
  gap: 14px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.science-list li {
  display: grid;
  gap: 4px;
  padding-left: 18px;
  border-left: 2px solid rgba(101,228,255,.18);
}

.science-list a {
  color: var(--text);
  font-weight: 800;
}

.science-list span {
  color: var(--muted);
  line-height: 1.5;
}

.toolbar-controls {
  display: flex;
  align-items: center;
  gap: 10px;
  justify-content: flex-end;
}
.view-count { min-height: 38px; display: inline-flex; align-items: center; }

.grid { align-items: stretch; }
.card {
  display: flex;
  flex-direction: column;
}
.card .tags { margin-top: auto; }
.card .open { align-self: flex-start; }
.card p { max-width: 62ch; }
body.card-compact .grid { grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 12px; }
body.card-compact .card { min-height: 190px; padding: 18px; border-radius: 22px; }
body.card-compact .card h2 { font-size: 1.12rem; margin: 12px 0 8px; }
body.card-compact .card p { font-size: .87rem; line-height: 1.45; margin-bottom: 14px; }
body.card-compact .open { margin-top: 14px; }

.toc-panel a.active {
  color: var(--text);
  border-color: rgba(101,228,255,.34);
  background: linear-gradient(90deg, rgba(101,228,255,.14), transparent);
  padding-left: 10px;
  border-radius: 10px;
}

/* Interactive RFC graph: contained controls + readable legend */
.map-overlay {
  position: fixed;
  inset: 0;
  z-index: 90;
  display: none;
  overflow: hidden;
  background:
    radial-gradient(circle at 20% 8%, rgba(101,228,255,.18), transparent 30%),
    radial-gradient(circle at 82% 18%, rgba(255,82,168,.14), transparent 28%),
    linear-gradient(180deg, rgba(5,8,18,.98), rgba(2,4,12,.99));
}
.map-overlay.active { display: grid; grid-template-rows: auto 1fr; }
.map-header {
  position: relative;
  z-index: 3;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 18px clamp(18px, 3vw, 36px);
  border-bottom: 1px solid rgba(101,228,255,.14);
  background: rgba(4,8,18,.72);
  backdrop-filter: blur(18px);
  box-shadow: 0 18px 48px rgba(0,0,0,.34);
}
.map-header .eyebrow {
  margin: 0;
  letter-spacing: .18em;
  white-space: nowrap;
}
.map-container {
  position: relative;
  min-height: 0;
  overflow: hidden;
  background-image:
    linear-gradient(rgba(101,228,255,.045) 1px, transparent 1px),
    linear-gradient(90deg, rgba(101,228,255,.045) 1px, transparent 1px);
  background-size: 64px 64px;
}
.map-container svg { display: block; width: 100%; height: 100%; }
.map-legend {
  position: absolute;
  left: clamp(16px, 2.5vw, 30px);
  top: clamp(16px, 2.5vw, 30px);
  z-index: 2;
  width: min(300px, calc(100vw - 32px));
  max-height: calc(100% - 32px);
  overflow: auto;
  padding: 18px;
  border: 1px solid rgba(101,228,255,.20);
  border-radius: 24px;
  color: var(--text);
  background: linear-gradient(145deg, rgba(8,14,30,.92), rgba(6,9,20,.82));
  box-shadow: 0 24px 70px rgba(0,0,0,.42), inset 0 1px 0 rgba(255,255,255,.08);
  backdrop-filter: blur(16px);
}
.legend-group + .legend-group { margin-top: 18px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,.08); }
.legend-group h4 {
  margin: 0 0 12px;
  color: var(--text);
  font-size: .82rem;
  text-transform: uppercase;
  letter-spacing: .14em;
}
.legend-item {
  display: grid;
  grid-template-columns: 22px 1fr;
  align-items: center;
  gap: 10px;
  min-height: 30px;
  color: var(--text2);
  font-size: .93rem;
  line-height: 1.25;
}
.legend-color {
  width: 13px;
  height: 13px;
  border-radius: 999px;
  box-shadow: 0 0 16px currentColor;
}
.legend-line {
  width: 20px;
  height: 0;
  border-radius: 999px;
  border-top: 2px solid rgba(226,232,255,.78);
}
.link {
  fill: none;
  stroke: rgba(226,232,255,.45);
  stroke-width: 1.8;
}
.link.update-chain { stroke: var(--amber); stroke-dasharray: 8 6; }
.link.threat { stroke: var(--pink); stroke-dasharray: 2 5; }
.link.highlight { stroke-width: 3.5; filter: drop-shadow(0 0 8px currentColor); }
.link.dimmed, .node.dimmed { opacity: .18; }
.node { cursor: pointer; transition: opacity .18s ease; }
.node rect {
  rx: 13;
  ry: 13;
  fill: rgba(10,16,32,.92);
  stroke: var(--cyan);
  stroke-width: 1.4;
  filter: drop-shadow(0 12px 18px rgba(0,0,0,.45));
}
.node-link rect { stroke: var(--violet); }
.node-routing rect, .node-security rect { stroke: var(--cyan); }
.node-transport rect { stroke: var(--amber); }
.node-application rect { stroke: var(--pink); }
.node-monitoring rect { stroke: var(--green); }
.node text {
  fill: var(--text);
  font-size: 10px;
  font-weight: 800;
  text-anchor: middle;
  pointer-events: none;
}
.node .node-rfc { fill: var(--muted); font-size: 9px; font-weight: 700; }

.doc-body pre { max-width: 100%; }
.doc-body.focus pre { max-width: 100%; }
.reader-tools { min-height: 58px; }

@media (max-width: 780px) {
  .hero-actions { justify-content: flex-start; }
  .hero-action { width: 100%; justify-content: center; }
  .study-plan { padding: 20px 16px; border-radius: 26px; }
  .study-plan-grid,
  .study-track-grid { grid-template-columns: 1fr; }
  .study-status-row { align-items: stretch; }
  .study-status-row .reader-btn { width: 100%; }
  .searchbox input { min-width: 0; }
  .toolbar-controls { width: 100%; justify-content: space-between; }
  .toolbar-controls .reader-btn { flex: 1; }
  .map-overlay.active { grid-template-rows: auto 1fr; }
  .map-header { align-items: flex-start; flex-direction: column; padding: 14px 16px; }
  .map-header .eyebrow { white-space: normal; }
  .map-legend {
    left: 12px;
    right: 12px;
    top: 12px;
    width: auto;
    max-height: 45%;
    border-radius: 18px;
  }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: .001ms !important;
    animation-iteration-count: 1 !important;
    scroll-behavior: auto !important;
    transition-duration: .001ms !important;
  }
  .eyebrow, .num::before, .study-progress-bar, .arp-flowchart-panel::before { animation: none !important; }
  .card:hover, .hero-action:hover, button.reader-btn:hover, button.filter:hover { transform: none !important; }
}


"""


INDEX_JS = r"""
const q = document.querySelector('#q');
const cards = [...document.querySelectorAll('.card')];
const empty = document.querySelector('.empty');
const count = document.querySelector('#count');
const filters = [...document.querySelectorAll('.filter')];
const densityToggleBtn = document.querySelector('#density-toggle');
const viewNotesBtn = document.querySelector('#view-notes');
const backToGridBtn = document.querySelector('#back-to-grid');
const notesView = document.querySelector('#notes-view');
const mainGrid = document.querySelector('main');
const notesContainer = document.querySelector('#notes-container');
const exportBtn = document.querySelector('#export-notes');
const importBtn = document.querySelector('#import-notes-btn');
const importFile = document.querySelector('#import-notes-file');
const noteFilterBtns = [...document.querySelectorAll('.notes-filter-btn')];
const toolbar = document.querySelector('.toolbar');
const studyPathBtns = [...document.querySelectorAll('.study-path-btn')];
const clearStudyPathBtn = document.querySelector('#clear-study-path');
const activeStudyPathEl = document.querySelector('#active-study-path');
const ifThenCueInput = document.querySelector('#if-then-cue');
const ifThenActionInput = document.querySelector('#if-then-action');
const ifThenPreview = document.querySelector('#if-then-preview');
const ifThenStatus = document.querySelector('#if-then-status');
const saveIfThenBtn = document.querySelector('#save-if-then');
const clearIfThenBtn = document.querySelector('#clear-if-then');
const emptyDefaultText = empty?.textContent || '';

function readJSON(key, fallback = {}) {
  try { return JSON.parse(localStorage.getItem(key) || JSON.stringify(fallback)); }
  catch (err) { return fallback; }
}

function writeJSON(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); }
  catch (err) { console.warn(`Could not save ${key}`, err); }
}

function setOverlayOpen(overlay, open) {
  if (!overlay) return;
  overlay.classList.toggle('active', open);
  overlay.setAttribute('aria-hidden', String(!open));
}

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
let activeStudyPath = '';
let activeStudyRfcSet = null;

let savedDensity = 'comfortable';
try { savedDensity = localStorage.getItem('rfc_card_density') || 'comfortable'; }
catch (err) { savedDensity = 'comfortable'; }
document.body.classList.toggle('card-compact', savedDensity === 'compact');
if (densityToggleBtn) densityToggleBtn.textContent = savedDensity === 'compact' ? 'Comfort cards' : 'Compact cards';
let currentSession = [];
let sessionIdx = 0;
let sessionStats = { reviewed: 0, mastered: 0, dueTomorrow: 0 };

const w = [0.4, 0.6, 2.4, 5.8, 4.93, 0.94, 0.86, 0.01, 1.49, 0.14, 0.94, 2.18, 0.05, 0.34, 1.26, 0.29, 2.61];

function getSRSData() {
  return readJSON('rfc_srs_state_fsrs');
}

function saveSRSData(state) {
  writeJSON('rfc_srs_state_fsrs', state);
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
  setOverlayOpen(studyOverlay, true); studySummary.classList.remove('active');
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

if (closeStudyBtn) closeStudyBtn.addEventListener('click', () => setOverlayOpen(studyOverlay, false));
document.querySelector('#finish-study')?.addEventListener('click', () => setOverlayOpen(studyOverlay, false));
document.querySelector('#restart-study').addEventListener('click', () => initStudySession());
if (startStudyBtn) startStudyBtn.addEventListener('click', () => initStudySession(false));
if (studyAllBtn) studyAllBtn.addEventListener('click', () => initStudySession(true));

const resetSrsBtn = document.querySelector("#reset-srs");
if (resetSrsBtn) resetSrsBtn.addEventListener("click", () => { if(confirm("Wipe all FSRS progress?")) { try { localStorage.removeItem("rfc_srs_state_fsrs"); } catch (err) {} location.reload(); } });

window.addEventListener('keydown', (e) => {
  if (!studyOverlay || !studyOverlay.classList.contains('active')) return;
  if (e.key === 'Escape') setOverlayOpen(studyOverlay, false);
  if (e.key === ' ') { e.preventDefault(); if (!cardContainer.classList.contains('flipped')) cardContainer.click(); }
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
    { source: "793", target: "791", type: "dependency" }, { source: "768", target: "791", type: "dependency" },
    { source: "1035", target: "768", type: "dependency" }, { source: "1035", target: "793", type: "dependency" },
    { source: "4271", target: "793", type: "dependency" }, { source: "2131", target: "768", type: "dependency" },
    { source: "5321", target: "793", type: "dependency" }, { source: "3954", target: "768", type: "dependency" },
    { source: "7011", target: "768", type: "dependency" }, { source: "2616", target: "793", type: "dependency" },
    { source: "7230", target: "793", type: "dependency" }, { source: "7540", target: "793", type: "dependency" },
    { source: "2328", target: "791", type: "dependency" }, { source: "826", target: "791", type: "dependency" },
    { source: "2460", target: "791", type: "update-chain" }, { source: "7230", target: "2616", type: "update-chain" },
    { source: "1035", target: "5321", type: "threat" }, { source: "1035", target: "768", type: "threat" },
    { source: "4271", target: "2328", type: "threat" }, { source: "791", target: "2460", type: "threat" },
    { source: "793", target: "7540", type: "threat" },
  ]
};

function initMap() {
  if (!mapContainer) return;
  const nodes = GRAPH_DATA.nodes; if (!nodes.length) { console.warn("No nodes found"); return; }
  const nodeIds = new Set(nodes.map(n => n.id));
  const links = GRAPH_DATA.links.filter(l => nodeIds.has(l.source) && nodeIds.has(l.target)).map(l => ({...l}));

  const width = mapContainer.clientWidth || window.innerWidth;
  const height = mapContainer.clientHeight || window.innerHeight;

  mapContainer.querySelector('svg')?.remove();
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('width', '100%');
  svg.setAttribute('height', '100%');
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'RFC dependency graph');
  const g = document.createElementNS(ns, 'g');
  svg.appendChild(g);
  mapContainer.appendChild(svg);

  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.max(180, Math.min(width, height) * 0.36);
  const priority = new Set(['768', '791', '792', '793', '826', '1035', '2131', '2328', '3954', '4271', '5321', '7011', '7230', '7540']);
  const visibleNodes = nodes.filter(n => priority.has(n.id));
  const visibleIds = new Set(visibleNodes.map(n => n.id));
  const visibleLinks = links.filter(l => visibleIds.has(l.source) && visibleIds.has(l.target));
  visibleNodes.forEach((node, index) => {
    const angle = (index / visibleNodes.length) * Math.PI * 2 - Math.PI / 2;
    node.x = centerX + Math.cos(angle) * radius;
    node.y = centerY + Math.sin(angle) * radius;
  });
  const byId = new Map(visibleNodes.map(node => [node.id, node]));
  const linkEls = [];
  const nodeEls = [];

  visibleLinks.forEach(link => {
    const source = byId.get(link.source);
    const target = byId.get(link.target);
    if (!source || !target) return;
    const path = document.createElementNS(ns, 'path');
    const midX = (source.x + target.x) / 2;
    const midY = (source.y + target.y) / 2;
    const curveX = midX + (centerX - midX) * 0.24;
    const curveY = midY + (centerY - midY) * 0.24;
    path.setAttribute('d', `M${source.x},${source.y} Q${curveX},${curveY} ${target.x},${target.y}`);
    path.setAttribute('class', `link ${link.type}`);
    path.dataset.source = source.id;
    path.dataset.target = target.id;
    g.appendChild(path);
    linkEls.push(path);
  });

  visibleNodes.forEach(node => {
    const group = document.createElementNS(ns, 'g');
    group.setAttribute('class', `node node-${node.layer}`);
    group.setAttribute('transform', `translate(${node.x},${node.y})`);
    group.setAttribute('tabindex', '0');
    group.setAttribute('role', 'link');
    group.setAttribute('aria-label', `Open RFC ${node.num}: ${node.name}`);
    group.dataset.id = node.id;
    const nodeWidth = Math.max(120, node.name.length * 8 + 30);
    const title = document.createElementNS(ns, 'title');
    title.textContent = `RFC ${node.num}: ${node.name}`;
    const rect = document.createElementNS(ns, 'rect');
    rect.setAttribute('width', String(nodeWidth));
    rect.setAttribute('height', '54');
    rect.setAttribute('x', String(-nodeWidth / 2));
    rect.setAttribute('y', '-27');
    const label = document.createElementNS(ns, 'text');
    label.setAttribute('dy', '-4');
    label.style.fontSize = '11px';
    label.textContent = node.name;
    const num = document.createElementNS(ns, 'text');
    num.setAttribute('class', 'node-rfc');
    num.setAttribute('dy', '14');
    num.textContent = `RFC ${node.num}`;
    group.append(title, rect, label, num);
    const open = () => { window.location.href = `rfc/rfc${node.num}.html`; };
    group.addEventListener('click', open);
    group.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(); } });
    group.addEventListener('pointerenter', () => highlightGraph(node.id, nodeEls, linkEls));
    group.addEventListener('pointerleave', () => clearGraphHighlight(nodeEls, linkEls));
    g.appendChild(group);
    nodeEls.push(group);
  });

  let transform = { x: 0, y: 0, scale: 1 };
  let dragStart = null;
  const applyTransform = () => g.setAttribute('transform', `translate(${transform.x} ${transform.y}) scale(${transform.scale})`);
  svg.addEventListener('wheel', (event) => {
    event.preventDefault();
    transform.scale = Math.min(3, Math.max(0.45, transform.scale + (event.deltaY > 0 ? -0.08 : 0.08)));
    applyTransform();
  }, { passive: false });
  svg.addEventListener('pointerdown', (event) => { dragStart = { x: event.clientX - transform.x, y: event.clientY - transform.y }; svg.setPointerCapture(event.pointerId); });
  svg.addEventListener('pointermove', (event) => {
    if (!dragStart) return;
    transform.x = event.clientX - dragStart.x;
    transform.y = event.clientY - dragStart.y;
    applyTransform();
  });
  svg.addEventListener('pointerup', () => { dragStart = null; });
}

function highlightGraph(id, nodeEls, linkEls) {
  const neighbors = new Set([id]);
  linkEls.forEach(link => {
    if (link.dataset.source === id) neighbors.add(link.dataset.target);
    if (link.dataset.target === id) neighbors.add(link.dataset.source);
  });
  nodeEls.forEach(node => node.classList.toggle('dimmed', !neighbors.has(node.dataset.id)));
  linkEls.forEach(link => {
    const active = link.dataset.source === id || link.dataset.target === id;
    link.classList.toggle('highlight', active);
    link.classList.toggle('dimmed', !active);
  });
}

function clearGraphHighlight(nodeEls, linkEls) {
  nodeEls.forEach(node => node.classList.remove('dimmed'));
  linkEls.forEach(link => link.classList.remove('dimmed', 'highlight'));
}

function setStudyPath(pathId, scrollIntoView = false) {
  const activeBtn = studyPathBtns.find((btn) => btn.dataset.path === pathId) || null;
  activeStudyPath = activeBtn?.dataset.label || '';
  activeStudyRfcSet = activeBtn ? new Set((activeBtn.dataset.rfcs || '').split(' ').filter(Boolean)) : null;
  studyPathBtns.forEach((btn) => btn.classList.toggle('active', btn === activeBtn));
  if (activeStudyPathEl) activeStudyPathEl.textContent = activeStudyPath || 'Full library mode';
  if (clearStudyPathBtn) clearStudyPathBtn.disabled = !activeBtn;
  try { localStorage.setItem('rfc_active_study_path', activeBtn?.dataset.path || ''); } catch (err) {}
  applyFilters();
  if (scrollIntoView) document.querySelector('#rfc-grid')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function updateIfThenPreview() {
  if (!ifThenPreview) return;
  const cue = ifThenCueInput?.value.trim() || '';
  const action = ifThenActionInput?.value.trim() || '';
  if (!cue && !action) {
    ifThenPreview.textContent = 'If your cue happens, then your study move lives here. Tiny counts. Tiny is how empires are built.';
    return;
  }
  ifThenPreview.textContent = `If ${cue || '...'}, then ${action || '...'}.`;
}

function loadIfThenPlan() {
  const saved = readJSON('rfc_if_then_plan', { cue: '', action: '' });
  if (ifThenCueInput) ifThenCueInput.value = saved.cue || '';
  if (ifThenActionInput) ifThenActionInput.value = saved.action || '';
  updateIfThenPreview();
}

if (openMapBtn) openMapBtn.addEventListener('click', () => { setOverlayOpen(mapOverlay, true); setTimeout(initMap, 100); });
if (closeMapBtn) closeMapBtn.addEventListener('click', () => setOverlayOpen(mapOverlay, false));

window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && mapOverlay?.classList.contains('active')) setOverlayOpen(mapOverlay, false);
});

function applyFilters() {
  const term = q?.value.trim().toLowerCase() || '';
  let visible = 0;
  for (const card of cards) {
    const tagHit = activeTag === 'all' || card.dataset.tags.split(' ').includes(activeTag);
    const studyHit = !activeStudyRfcSet || activeStudyRfcSet.has(card.dataset.rfc);
    const hit = tagHit && studyHit && card.dataset.search.includes(term);
    card.style.display = hit ? '' : 'none';
    if (hit) visible++;
  }
  if (count) count.textContent = `${visible} of ${cards.length} shown${activeStudyPath ? ` · Path: ${activeStudyPath}` : ''}`;
  if (empty) {
    empty.style.display = visible ? 'none' : 'block';
    empty.textContent = activeStudyPath ? `No RFCs match the current search inside "${activeStudyPath}". Try clearing the search or switching tracks.` : emptyDefaultText;
  }
}

function renderNotes() {
  if (!notesContainer) return;
  const allNotes = readJSON('rfc_notes');
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
    header.innerHTML = `<span>RFC ${num}: ${rfcTitle}</span> <a href="rfc/rfc${num}.html">View RFC</a>`;
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
    notesContainer.innerHTML = rfcNums.length === 0 ? '<div class="notes-empty">You haven\'t added any notes yet.</div>' : `<div class="notes-empty">No notes match the "${activeNoteFilter}" filter.</div>`;
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

q?.addEventListener('input', applyFilters);
studyPathBtns.forEach((btn) => btn.addEventListener('click', () => setStudyPath(btn.dataset.path, true)));
if (clearStudyPathBtn) clearStudyPathBtn.addEventListener('click', () => setStudyPath('', false));
if (densityToggleBtn) densityToggleBtn.addEventListener('click', () => {
  const compact = !document.body.classList.contains('card-compact');
  document.body.classList.toggle('card-compact', compact);
  try { localStorage.setItem('rfc_card_density', compact ? 'compact' : 'comfortable'); } catch (err) {}
  densityToggleBtn.textContent = compact ? 'Comfort cards' : 'Compact cards';
});
filters.forEach(btn => btn.addEventListener('click', () => { activeTag = btn.dataset.tag; filters.forEach(item => item.classList.toggle('active', item === btn)); applyFilters(); }));
noteFilterBtns.forEach(btn => btn.addEventListener('click', () => { activeNoteFilter = btn.dataset.filter; noteFilterBtns.forEach(b => b.classList.toggle('active', b === btn)); renderNotes(); }));
if (viewNotesBtn) viewNotesBtn.addEventListener('click', () => toggleNotesView(true));
if (backToGridBtn) backToGridBtn.addEventListener('click', () => toggleNotesView(false));
if (exportBtn) exportBtn.addEventListener('click', () => {
  const allNotes = localStorage.getItem('rfc_notes') || '{}';
  const blob = new Blob([allNotes], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = `rfc-annotations-${new Date().toISOString().split('T')[0]}.json`; a.click(); URL.revokeObjectURL(url);
});
if (importBtn && importFile) importBtn.addEventListener('click', () => importFile.click());
if (importFile) importFile.addEventListener('change', (e) => {
  const file = e.target.files[0]; if (!file) return;
  const reader = new FileReader();
  reader.onload = (event) => {
    try {
      const imported = JSON.parse(event.target.result);
      const current = readJSON('rfc_notes');
      for (const rfcNum in imported) {
        if (!current[rfcNum]) current[rfcNum] = imported[rfcNum];
        else current[rfcNum] = { ...current[rfcNum], ...imported[rfcNum] };
      }
      writeJSON('rfc_notes', current); renderNotes(); alert('Notes imported and merged successfully!');
    } catch (err) { alert('Error importing notes: Invalid JSON file'); }
  };
  reader.readAsText(file);
});
ifThenCueInput?.addEventListener('input', updateIfThenPreview);
ifThenActionInput?.addEventListener('input', updateIfThenPreview);
if (saveIfThenBtn) saveIfThenBtn.addEventListener('click', () => {
  const cue = ifThenCueInput?.value.trim() || '';
  const action = ifThenActionInput?.value.trim() || '';
  writeJSON('rfc_if_then_plan', { cue, action });
  if (ifThenStatus) ifThenStatus.textContent = cue && action ? 'Saved locally. Future you now has a cue, a move, and slightly fewer excuses.' : 'Saved, though a specific cue and action will work better.';
  updateIfThenPreview();
});
if (clearIfThenBtn) clearIfThenBtn.addEventListener('click', () => {
  if (ifThenCueInput) ifThenCueInput.value = '';
  if (ifThenActionInput) ifThenActionInput.value = '';
  writeJSON('rfc_if_then_plan', { cue: '', action: '' });
  if (ifThenStatus) ifThenStatus.textContent = 'Pact cleared. The gremlin has been temporarily released back into the wild.';
  updateIfThenPreview();
});

loadIfThenPlan();
try {
  const savedStudyPath = localStorage.getItem('rfc_active_study_path') || '';
  if (savedStudyPath) setStudyPath(savedStudyPath, false);
  else applyFilters();
} catch (err) {
  applyFilters();
}
updateDueCounts();
window.addEventListener('scroll', () => toolbar?.classList.toggle('scrolled', window.scrollY > 12), { passive: true });
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

function initActiveToc(headings) {
  if (!headings || !headings.length || !('IntersectionObserver' in window)) return;
  const links = new Map([...toc.querySelectorAll('a[href^="#"]')].map(a => [decodeURIComponent(a.hash.slice(1)), a]));
  const setActive = (id) => {
    links.forEach(link => link.classList.toggle('active', link.getAttribute('href') === `#${id}`));
  };
  const observer = new IntersectionObserver((entries) => {
    const visible = entries.filter(entry => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (visible?.target?.id) setActive(visible.target.id);
  }, { rootMargin: '-18% 0px -70% 0px', threshold: [0, .25, .5, 1] });
  headings.forEach(heading => heading.id && observer.observe(heading));
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

function isAsciiDiagramLine(line) {
  const trimmed = line.trim();
  if (!trimmed) return false;
  if (/^[+|\-:\s]+$/.test(trimmed) && /[+|]/.test(trimmed) && trimmed.length >= 8) return true;
  if (/\+[-+=]{3,}\+/.test(trimmed)) return true;
  if (/\|.*\|/.test(trimmed) && trimmed.length >= 12) return true;
  if (/^(?:\d+\s+){6,}\d+$/.test(trimmed)) return true;
  return false;
}

function renderModernAsciiDiagram(lines) {
  const panel = document.createElement('figure');
  panel.className = 'modern-ascii-diagram';
  panel.setAttribute('role', 'img');
  panel.setAttribute('aria-label', 'Modernized RFC packet diagram');

  const kicker = document.createElement('figcaption');
  kicker.className = 'modern-diagram-kicker';
  kicker.textContent = 'Modernized packet graphic';
  panel.appendChild(kicker);

  const grid = document.createElement('div');
  grid.className = 'modern-diagram-grid';
  const rows = lines
    .map(line => line.split('|').map(cell => cell.trim()).filter(Boolean))
    .filter(cells => cells.length > 0 && cells.some(cell => /[A-Za-z0-9]/.test(cell)));

  if (!rows.length) {
    const fallback = document.createElement('div');
    fallback.className = 'modern-diagram-fallback';
    fallback.textContent = lines.join('\n');
    grid.appendChild(fallback);
  } else {
    rows.forEach((cells) => {
      const row = document.createElement('div');
      row.className = 'modern-diagram-row';
      row.style.setProperty('--cell-count', String(cells.length));
      cells.forEach((label) => {
        const cell = document.createElement('div');
        cell.className = 'modern-diagram-cell';
        cell.textContent = label.replace(/\s+/g, ' ');
        row.appendChild(cell);
      });
      grid.appendChild(row);
    });
  }
  panel.appendChild(grid);
  return panel;
}

function modernizeAsciiGraphics() {
  document.querySelectorAll('.rfc-source-shell pre').forEach((pre) => {
    const lines = pre.textContent.split('\n');
    const parts = [];
    let index = 0;
    let changed = false;
    while (index < lines.length) {
      if (!isAsciiDiagramLine(lines[index])) {
        const start = index;
        while (index < lines.length && !isAsciiDiagramLine(lines[index])) index++;
        const text = lines.slice(start, index).join('\n');
        if (text.trim()) parts.push({ type: 'text', lines: text });
        continue;
      }
      const start = index;
      let diagramCount = 0;
      while (index < lines.length && (isAsciiDiagramLine(lines[index]) || !lines[index].trim())) {
        if (isAsciiDiagramLine(lines[index])) diagramCount++;
        index++;
      }
      const block = lines.slice(start, index);
      if (diagramCount >= 3 && block.some(line => /\|.*\||\+[-+=]{3,}\+/.test(line))) {
        parts.push({ type: 'diagram', lines: block });
        changed = true;
      } else {
        parts.push({ type: 'text', lines: block.join('\n') });
      }
    }
    if (!changed) return;
    const fragment = document.createDocumentFragment();
    parts.forEach((part) => {
      if (part.type === 'diagram') {
        fragment.appendChild(renderModernAsciiDiagram(part.lines));
      } else if (part.lines.trim()) {
        const textPre = document.createElement('pre');
        textPre.textContent = part.lines.replace(/^\n+|\n+$/g, '');
        fragment.appendChild(textPre);
      }
    });
    pre.replaceWith(fragment);
  });
}

addEventListener('scroll', updateProgress, { passive: true });
if (focusBtn) focusBtn.addEventListener('click', () => body.classList.toggle('focus'));
if (comfyBtn) comfyBtn.addEventListener('click', () => body.classList.toggle('comfy'));
if (topBtn) topBtn.addEventListener('click', () => scrollTo({ top: 0, behavior: 'smooth' }));
setHeaderPanelDefault();
modernizeAsciiGraphics();
const headings = makeToc();
initActiveToc(headings);
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
            body, inserted_enhancements = inject_all_enhancements(meta.num, body)
            inline_header_reference = "render_inline_header_reference" in inserted_enhancements
            body = format_rfc_source_body(body, "RFC Editor HTML")
        elif build.text_ok and build.text_path:
            linked_text = link_plain_metadata_refs(html.escape(read_text(build.text_path)), local_nums)
            body = f"<pre>{linked_text}</pre>"
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
    elif build.text_ok and build.text_path:
        linked_text = link_plain_metadata_refs(html.escape(read_text(build.text_path)), local_nums, local_ext=".xhtml")
        source = f"<pre>{linked_text}</pre>"
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
