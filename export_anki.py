
import csv
import re
from pathlib import Path
import html

# Mock ebooklib to avoid import errors if not installed
import sys
from unittest.mock import MagicMock
sys.modules["ebooklib"] = MagicMock()
sys.modules["ebooklib.epub"] = MagicMock()

import build_rfc_collection as brc

def clean_text(text):
    if not text:
        return ""
    # Remove HTML if any
    text = re.sub(r'<[^>]+>', '', text)
    # Unescape HTML entities
    text = html.unescape(text)
    return text.strip()

def export_to_anki():
    # 1. Gather all RFCs in data/txt
    txt_dir = Path("data/txt")
    rfc_files = list(txt_dir.glob("rfc*.txt"))
    
    # 2. Process them to get metadata
    builds = []
    
    # First, use the predefined ones in brc.RFCS
    seed_nums = {meta.num for meta in brc.RFCS}
    for meta in brc.RFCS:
        txt_path = txt_dir / f"rfc{meta.num}.txt"
        build = brc.RFCBuild(meta=meta, text_path=txt_path, text_ok=txt_path.exists())
        builds.append(build)
        
    # Then, add the rest from the directory
    for f in rfc_files:
        num_match = re.search(r'rfc(\d+)\.txt', f.name)
        if not num_match:
            continue
        num = int(num_match.group(1))
        if num in seed_nums:
            continue
            
        # Create a build object for derived metadata
        dummy_meta = brc.RFCMeta(num, f"RFC {num}", "", ("update-chain",), update_chain=True)
        build = brc.RFCBuild(meta=dummy_meta, text_path=f, text_ok=True)
        # Use brc's logic to infer title and tags
        build.meta = brc.derived_meta(num, build)
        builds.append(build)

    cards = []
    
    # Psychology: Use Tags for filtering in Anki
    # Psychology: Active Recall - RFC Number to Title
    for b in builds:
        num = b.meta.num
        title = b.meta.title
        tags = " ".join(b.meta.tags)
        
        # Card 1: Number -> Title
        cards.append({
            "Front": f"What is the title/topic of <b>RFC {num}</b>?",
            "Back": title,
            "Tags": f"rfc_number_to_title {tags}"
        })
        
        # Card 2: Title -> Number (Reverse)
        cards.append({
            "Front": f"What is the RFC number for <b>{title}</b>?",
            "Back": f"RFC {num}",
            "Tags": f"rfc_title_to_number {tags}"
        })
        
        # Card 3: Significance/Hunting Relevance (if available)
        if b.meta.relevance and not b.meta.update_chain:
            cards.append({
                "Front": f"RFC {num} ({title}): Why is this RFC relevant for <b>threat hunting</b>?",
                "Back": b.meta.relevance,
                "Tags": f"relevance {tags}"
            })

    # Header Field Cards
    for num, header in brc.HEADER_REFERENCES.items():
        title = header["title"]
        for field_name, bit_width, purpose in header["fields"]:
            # Psychology: Atomic cards - one field at a time
            cards.append({
                "Front": f"{title}: What is the purpose of the <b>{field_name}</b> field ({bit_width} bits)?",
                "Back": purpose,
                "Tags": f"header_field {field_name.lower().replace(' ', '_')} {num}"
            })

    # Threat Indicator Cards
    for num, indicators in brc.THREAT_INDICATORS.items():
        title = next((b.meta.title for b in builds if b.meta.num == num), f"RFC {num}")
        for ind in indicators:
            # Psychology: Comparison (Normal vs Malicious)
            cards.append({
                "Front": f"RFC {num} ({title}) - Threat Indicator: <b>{ind['name']}</b><br><br>What is the <b>malicious indicator</b> compared to normal behavior?",
                "Back": f"<b>Normal:</b> {ind['normal']}<br><br><b>Malicious:</b> {ind['malicious']}<br><br><b>Severity:</b> {ind['sev'].upper()}",
                "Tags": f"threat_indicator {ind['sev']} {num}"
            })

    # 3. Write to CSV
    with open("rfc_anki_deck.csv", "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["Front", "Back", "Tags"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter="\t")
        # No header for Anki import usually, or we specify it in Anki
        for card in cards:
            writer.writerow({
                "Front": card["Front"],
                "Back": card["Back"],
                "Tags": card["Tags"]
            })
            
    print(f"Exported {len(cards)} cards to rfc_anki_deck.csv")

if __name__ == "__main__":
    export_to_anki()
