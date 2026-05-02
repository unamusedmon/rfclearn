"""Configuration and constants for RFC Learn."""

from pathlib import Path
import re

from .models import RFCMeta

# ROOT should point to the repository root (parent of this package)
ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
SITE_DIR = ROOT / "site"
EPUB_DIR = ROOT / "epub"
RFC_BASE = "https://www.rfc-editor.org/rfc/rfc{num}.{ext}"




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
    3954: {
        "title": "RFC 3954 NetFlow v9 Header",
        "note": "NetFlow v9 headers identify the exporter and sequence state needed to detect telemetry gaps or spoofed flow data.",
        "fields": [
            ("Version", 16, "Should be 9; mismatches indicate wrong protocol or malformed exporter traffic."),
            ("Count", 16, "Number of records in this packet; excessive counts or zero records can be abnormal."),
            ("sysUpTime", 32, "Exporter uptime in ms; non-monotonic jumps reveal resets or spoofed exporters."),
            ("UNIX Secs", 32, "Current seconds since epoch; large offsets from collector time indicate misconfiguration or replay."),
            ("Sequence", 32, "Incremental packet counter; gaps reveal packet loss or telemetry interference."),
            ("Source ID", 32, "Exporter sub-entity ID; unexpected IDs can indicate rogue or misconfigured exporters."),
        ],
    },
    7011: {
        "title": "RFC 7011 IPFIX Message Header",
        "note": "IPFIX headers drive telemetry normalization and help spot exporter spoofing or sequence manipulation.",
        "fields": [
            ("Version", 16, "Should be 0x000a (10); mismatches indicate legacy NetFlow or malformed traffic."),
            ("Length", 16, "Total length of IPFIX message; mismatches with L4 length indicate malformed packets."),
            ("Export Time", 32, "Seconds since epoch; used to detect replayed telemetry or clock drift."),
            ("Sequence", 32, "Incremental message counter; gaps signal packet loss or telemetry evasion."),
            ("Domain ID", 32, "Observation domain; used to distinguish exporters behind a single IP."),
        ],
    },
    7540: {
        "title": "RFC 7540 HTTP/2 Frame Header",
        "note": "HTTP/2 uses binary framing; the header identifies frame types and stream associations used in multiplexing abuse hunts.",
        "fields": [
            ("Length", 24, "Frame payload length; unexpected sizes can indicate fragmentation abuse or large-header attacks."),
            ("Type", 8, "Frame type (DATA, HEADERS, SETTINGS, etc.); unusual type sequences can reveal protocol smuggling."),
            ("Flags", 8, "Type-specific flags (END_STREAM, PADDING, etc.); watch for inconsistent or illegal flag use."),
            ("R", 1, "Reserved bit; MUST be zero; non-zero values are abnormal."),
            ("Stream ID", 31, "Identifies the stream; odd-numbered are client-initiated; watch for ID exhaustion or collisions."),
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


