# RFC Threat Hunting Library

<p align="center">
  <strong>A dark-mode, offline-first protocol field guide for network defenders.</strong><br>
  Curated RFCs, hunting notes, local cross-links, EPUB exports, and quick visual header references.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#whats-inside">What's Inside</a> •
  <a href="#header-field-panels">Header Panels</a> •
  <a href="#gitlab-pages">GitLab Pages</a> •
  <a href="#hunting-workflows">Hunting Workflows</a>
</p>

---

## Why this exists

Reading raw RFCs during an investigation is painful. This project turns a curated set of high-value networking RFCs into a local, searchable, dark-themed reference library built for threat hunters.

It combines:

- Cached RFC HTML/TXT sources from rfc-editor.org
- Analyst-focused relevance notes
- Local RFC cross-links, including update and obsoletion chains
- Protocol categories for routing, transport, security, monitoring, and application workflows
- EPUB exports for offline reading
- Header field quick-reference panels for major protocols

No runtime network calls are needed after the site is built.

---

## What's inside

Primary seed RFCs include:

| Area | RFCs |
|---|---|
| Transport | UDP 768, TCP 793, HTTP/2 7540 |
| Routing | IPv4 791, ICMP 792, ARP 826, OSPF 2328, BGP 4271, IPv6 2460 |
| Application | DNS 1035, DHCP 2131, SMTP 5321, HTTP 2616 / 7230 |
| Monitoring | NetFlow v9 3954, IPFIX 7011 |
| Security | IPsec architecture 4301, ESP 4303 |

The build also follows update, obsolete, and obsoleted-by relationships to pull related context RFCs.

---

## Header field panels

Selected RFC pages include a collapsible quick-reference sidebar with:

- A visual 0-31 bit layout diagram
- Field blocks sized to their bit widths
- Compact field reference table
- Hunting-relevant abnormal indicators

Currently covered:

- RFC 768: UDP header
- RFC 791: IPv4 header
- RFC 793: TCP header
- RFC 1035: DNS message header
- RFC 2131: DHCP message header
- RFC 2328: OSPFv2 packet header
- RFC 2460: IPv6 header
- RFC 4271: BGP message / UPDATE fields
- RFC 5321: SMTP command and reply fields

Example hunting notes:

- TCP Flags: SYN/ACK/RST/FIN combinations; watch for illegal flag combos, SYN floods, or RST injection.
- IPv4 TTL: Decrements each hop; unusually low or inconsistent TTL can indicate spoofing or traceroute probing.
- BGP Path Attributes: AS_PATH manipulation is the primary vector for route hijacking.

---

## Quick start

This project uses Python and `ebooklib` for EPUB generation.

If you have `uv`:

```bash
uv run --with ebooklib python build_rfc_collection.py
```

Or with a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python build_rfc_collection.py
```

Outputs:

```text
site/                                      Static website
epub/rfc-threat-hunting-complete.epub     Complete EPUB
epub/rfc-threat-hunting-by-category.epub  Category-grouped EPUB
```

Open the local site:

```bash
python3 -m http.server 8765 --directory site
```

Then browse:

```text
http://127.0.0.1:8765
```

---

## Project layout

```text
.
├── build_rfc_collection.py     # Fetch, parse, link, render site, and build EPUBs
├── requirements.txt            # Python dependencies
├── data/                       # Cached RFC sources
│   ├── html/
│   └── txt/
├── site/                       # Generated static site
│   ├── index.html
│   ├── assets/
│   └── rfc/
├── epub/                       # Generated EPUB books
└── tests/                      # Regression tests for generated header panels
```

---

## Testing

Run the regression tests:

```bash
python3 -m unittest discover -s tests -v
```

Syntax-check the builder:

```bash
python3 -m py_compile build_rfc_collection.py
```

If your system Python does not have `ebooklib`, tests still stub that dependency so the header-panel rendering tests can run without installing EPUB tooling.

---

## GitLab setup

You do not need GitHub to use GitLab. Create the project directly in GitLab, then add the GitLab remote.

### Option A: GitLab web UI

1. Go to GitLab.
2. Create a new blank project.
3. Copy the HTTPS or SSH clone URL.
4. Run one of these locally:

HTTPS:

```bash
git remote add origin https://gitlab.com/YOUR_NAMESPACE/YOUR_PROJECT.git
git push -u origin main
```

SSH:

```bash
git remote add origin git@gitlab.com:YOUR_NAMESPACE/YOUR_PROJECT.git
git push -u origin main
```

### Option B: GitLab CLI

If you install `glab`, you can create the project from this directory:

```bash
glab auth login
glab repo create YOUR_PROJECT --private=false --source=. --push
```

---

## GitLab Pages

This repo includes a GitLab Pages pipeline in `.gitlab-ci.yml`.

When pushed to GitLab, the pipeline:

1. Installs Python dependencies
2. Rebuilds the RFC site and EPUB files
3. Publishes `site/` as GitLab Pages
4. Keeps EPUB files as downloadable job artifacts

After the first successful pipeline, check:

```text
Project → Deploy → Pages
```

---

## Hunting workflows

Use this library when you need fast protocol context during:

- Packet capture triage
- SIEM field interpretation
- IDS signature review
- Firewall and routing anomaly analysis
- DNS tunneling investigations
- DHCP rogue-server hunts
- BGP leak and hijack reviews
- TCP scan, injection, and reset analysis
- IPv4/IPv6 fragmentation and evasion analysis

---

## Design notes

The site is intentionally:

- Dark themed for long investigation sessions
- Static and portable
- Usable offline
- Friendly to browser search
- Rich enough for analysts without hiding the original RFC text

---

## License and source material

RFC content is sourced from the RFC Editor cache under the terms applicable to RFC documents. This project adds local generation, styling, curation metadata, and analyst-focused reference material.

---

<p align="center">
  Built for defenders who read packets, chase weird fields, and keep receipts.
</p>
