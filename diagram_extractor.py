#!/usr/bin/env python3
"""Phase 1: Diagram Extraction

Extract ASCII art diagrams from RFC text files and store them in a JSON file.
"""

import hashlib
import json
import re
from pathlib import Path
from rfclearn.builder import is_ascii_diagram_line, DATA_DIR

def clean_rfc_text(text: str) -> str:
    """Strip RFC pagination noise like [Page X], form feeds, and standalone RFC markers."""
    # Strip form feeds
    text = text.replace('\f', '')
    
    # Regex for [Page 42]
    page_re = re.compile(r'^\s*\[Page \d+\]\s*$')
    # Regex for standalone RFC XXXX
    rfc_re = re.compile(r'^\s*RFC \d+\s*$')
    
    lines = text.splitlines()
    cleaned_lines = [
        line for line in lines 
        if not page_re.match(line) and not rfc_re.match(line)
    ]
    
    return '\n'.join(cleaned_lines)

def extract_diagram_blocks(text: str) -> list[str]:
    """Extract blocks of 3+ lines that look like ASCII diagrams."""
    lines = text.splitlines()
    blocks = []
    index = 0
    
    # Match the logic in modernize_ascii_html for consistency
    while index < len(lines):
        if not is_ascii_diagram_line(lines[index]):
            index += 1
            continue

        start = index
        diagram_count = 0
        # Allow internal empty lines within a diagram block
        while index < len(lines) and (is_ascii_diagram_line(lines[index]) or not lines[index].strip()):
            if is_ascii_diagram_line(lines[index]):
                diagram_count += 1
            index += 1

        block_lines = lines[start:index]
        # Filter: 3+ non-empty diagram lines AND must contain a box-like pattern
        if diagram_count >= 3 and any(re.search(r"\|.*\||\+[-+=]{3,}\+", line) for line in block_lines):
            # Normalizing by stripping trailing whitespace from the whole block
            blocks.append('\n'.join(block_lines).rstrip())
            
    return blocks

def main():
    pending_diagrams = {}
    txt_dir = DATA_DIR / "txt"
    
    if not txt_dir.exists():
        print(f"Error: {txt_dir} does not exist.")
        return

    txt_files = sorted(list(txt_dir.glob("*.txt")))
    print(f"Scanning {len(txt_files)} RFC text files...")
    
    for txt_file in txt_files:
        try:
            content = txt_file.read_text(encoding="utf-8", errors="replace")
            cleaned = clean_rfc_text(content)
            blocks = extract_diagram_blocks(cleaned)
            
            for block in blocks:
                # Use raw block for hashing
                block_hash = hashlib.sha256(block.encode('utf-8')).hexdigest()
                if block_hash not in pending_diagrams:
                    pending_diagrams[block_hash] = block
        except Exception as e:
            print(f"Failed to process {txt_file.name}: {e}")

    output_file = Path("pending_diagrams.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(pending_diagrams, f, indent=2, ensure_ascii=False)
    
    print(f"Done. Extracted {len(pending_diagrams)} unique diagrams to {output_file}")

if __name__ == "__main__":
    main()
