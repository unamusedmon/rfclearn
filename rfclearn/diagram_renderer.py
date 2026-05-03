#!/usr/bin/env python3
"""Advanced diagram rendering for RFC ASCII art replacement.

This module provides high-quality SVG-based visualizations to replace
ASCII diagrams in RFC documents with modern, accessible graphics.
"""

import html
import re
from typing import Optional


def parse_bit_field_diagram(lines: list[str]) -> list[dict]:
    """Parse RFC-style bit field diagrams into structured data.
    
    Example format:
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |       1       |       2       |       3       |       4       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    fields = []
    bit_positions = []
    
    for line in lines:
        stripped = line.strip()
        
        # Parse bit position markers
        if re.match(r'^\s*\d+(\s+\d+)*\s*$', stripped):
            positions = [int(x) for x in stripped.split()]
            bit_positions.extend(positions)
            continue
        
        # Parse field rows (lines with +--+-- patterns)
        if '+-' in stripped and '-+' in stripped:
            continue
        
        # Parse actual field content between border lines
        if '|' in stripped and not stripped.startswith('+'):
            # Extract field labels between | characters
            parts = stripped.split('|')
            for i, part in enumerate(parts):
                label = part.strip()
                if label and re.search(r'[A-Za-z0-9]', label):
                    # Determine field width based on character count
                    # Each character in ASCII diagram ≈ 1 bit (for small fields)
                    # or represents a byte (8 bits) for larger fields
                    char_width = len(part)
                    bit_width = max(8, char_width)  # Assume at least 8 bits
                    
                    fields.append({
                        'name': label,
                        'bit_width': bit_width,
                        'row': len([f for f in fields if 'row' in f]) // 4
                    })
    
    return fields


def render_bit_field_svg(fields: list[dict], title: str = "") -> str:
    """Render bit field diagram as SVG."""
    if not fields:
        return ""
    
    # Calculate layout
    bits_per_row = 32
    bit_width_px = 12
    row_height = 60
    label_height = 30
    padding = 20
    
    # Group fields into 32-bit rows
    rows = []
    current_row = []
    current_bits = 0
    
    for field in fields:
        field_bits = min(field.get('bit_width', 8), 32)
        if current_bits + field_bits > bits_per_row:
            if current_row:
                rows.append(current_row)
            current_row = [field]
            current_bits = field_bits
        else:
            current_row.append(field)
            current_bits += field_bits
    
    if current_row:
        rows.append(current_row)
    
    # Calculate dimensions
    svg_width = bits_per_row * bit_width_px + padding * 2
    svg_height = label_height + len(rows) * row_height + padding * 2
    
    # Build SVG
    svg_parts = [
        f'<svg class="rfc-bit-diagram" viewBox="0 0 {svg_width} {svg_height}" ',
        f'role="img" aria-label="{html.escape(title or "Bit field diagram")}" ',
        'xmlns="http://www.w3.org/2000/svg">',
        f'<desc>Protocol header bit field layout showing field names and positions</desc>',
        f'<defs>',
        f'  <style>',
        f'    .bit-grid {{ stroke: #94a3b8; stroke-width: 0.5; fill: none; }}',
        f'    .field-block {{ fill: #3b82f6; opacity: 0.9; rx: 4; }}',
        f'    .field-label {{ fill: white; font-size: 11px; font-weight: 600; font-family: Inter, sans-serif; text-anchor: middle; }}',
        f'    .bit-label {{ fill: #64748b; font-size: 9px; font-family: "IBM Plex Mono", monospace; text-anchor: middle; }}',
        f'    .row-label {{ fill: #475569; font-size: 10px; font-family: Inter, sans-serif; }}',
        f'  </style>',
        f'</defs>'
    ]
    
    # Draw bit position labels
    for bit in range(0, bits_per_row + 1, 8):
        x = padding + bit * bit_width_px
        label = str(bit) if bit < 32 else "31"
        svg_parts.append(f'<text class="bit-label" x="{x}" y="{padding + 12}">{label}</text>')
    
    # Draw fields
    for row_idx, row_fields in enumerate(rows):
        y_base = padding + label_height + row_idx * row_height
        bit_offset = 0
        
        for field in row_fields:
            field_bits = min(field.get('bit_width', 8), 32 - bit_offset)
            field_width = field_bits * bit_width_px
            x = padding + bit_offset * bit_width_px
            
            # Draw field block
            svg_parts.append(
                f'<rect class="field-block" x="{x}" y="{y_base}" '
                f'width="{field_width}" height="{row_height - 10}" />'
            )
            
            # Draw field label (truncate if too long)
            label = field.get('name', '')[:12]
            svg_parts.append(
                f'<text class="field-label" x="{x + field_width / 2}" '
                f'y="{y_base + (row_height - 10) / 2 + 4}">{html.escape(label)}</text>'
            )
            
            bit_offset += field_bits
        
        # Draw row border
        row_width = bits_per_row * bit_width_px
        svg_parts.append(
            f'<rect class="bit-grid" x="{padding}" y="{y_base}" '
            f'width="{row_width}" height="{row_height - 10}" />'
        )
    
    svg_parts.append('</svg>')
    return ''.join(svg_parts)


def parse_flow_diagram(lines: list[str]) -> dict:
    """Parse ASCII flow diagrams into structured data.
    
    Example:
        +---------+               +----------+
        |         | user queries  |          |
        |  User   |-------------->| Resolver |
        | Program |               |          |
        +---------+               +----------+
    """
    boxes = []
    arrows = []
    
    box_pattern = re.compile(r'\+(?:-+)\+')
    cell_pattern = re.compile(r'\|(.*?)\|')
    arrow_pattern = re.compile(r'-+>|<[-]+|-->')
    
    current_box = None
    box_id = 0
    
    for line_num, line in enumerate(lines):
        # Check for box top/bottom
        if box_pattern.search(line):
            if current_box is None:
                # Start new box
                matches = list(box_pattern.finditer(line))
                for match in matches:
                    current_box = {
                        'id': box_id,
                        'x': match.start(),
                        'y': line_num,
                        'width': match.end() - match.start(),
                        'height': 1,
                        'label': ''
                    }
                    boxes.append(current_box)
                    box_id += 1
            else:
                # Close current box(es)
                current_box = None
            continue
        
        # Check for box content
        if current_box and '|' in line:
            cells = cell_pattern.findall(line)
            if cells:
                # Combine multi-line labels
                current_box['label'] += ' '.join(c.strip() for c in cells if c.strip())
            current_box['height'] += 1
        
        # Check for arrows
        if arrow_pattern.search(line):
            for match in arrow_pattern.finditer(line):
                arrows.append({
                    'x': match.start(),
                    'y': line_num,
                    'direction': 'right' if '>' in match.group() else 'left',
                    'label': ''
                })
    
    return {'boxes': boxes, 'arrows': arrows}


def render_flow_svg(diagram_data: dict, title: str = "") -> str:
    """Render flow diagram as SVG."""
    boxes = diagram_data.get('boxes', [])
    arrows = diagram_data.get('arrows', [])
    
    if not boxes:
        return ""
    
    # Calculate layout
    padding = 30
    min_box_width = 120
    min_box_height = 60
    box_spacing_x = 40
    box_spacing_y = 80
    
    # Simple grid layout
    num_boxes = len(boxes)
    cols = min(3, num_boxes)
    rows = (num_boxes + cols - 1) // cols
    
    svg_width = padding * 2 + cols * min_box_width + (cols - 1) * box_spacing_x
    svg_height = padding * 2 + rows * min_box_height + (rows - 1) * box_spacing_y + 40
    
    svg_parts = [
        f'<svg class="rfc-flow-diagram" viewBox="0 0 {svg_width} {svg_height}" ',
        f'role="img" aria-label="{html.escape(title or "Flow diagram")}" ',
        'xmlns="http://www.w3.org/2000/svg">',
        f'<desc>System architecture or data flow diagram</desc>',
        f'<defs>',
        f'  <style>',
        f'    .flow-box {{ fill: #1e293b; stroke: #3b82f6; stroke-width: 2; rx: 12; }}',
        f'    .flow-label {{ fill: #e2e8f0; font-size: 13px; font-weight: 600; font-family: Inter, sans-serif; text-anchor: middle; }}',
        f'    .flow-arrow {{ stroke: #64748b; stroke-width: 2; fill: none; marker-end: url(#arrowhead); }}',
        f'    .arrow-label {{ fill: #94a3b8; font-size: 10px; font-family: "IBM Plex Mono", monospace; text-anchor: middle; }}',
        f'  </style>',
        f'  <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">',
        f'    <polygon points="0 0, 10 3.5, 0 7" fill="#64748b" />',
        f'  </marker>',
        f'</defs>'
    ]
    
    # Draw boxes
    for idx, box in enumerate(boxes):
        col = idx % cols
        row = idx // cols
        x = padding + col * (min_box_width + box_spacing_x)
        y = padding + row * (min_box_height + box_spacing_y)
        
        label = box.get('label', f'Box {idx + 1}')[:20]
        
        svg_parts.append(
            f'<rect class="flow-box" x="{x}" y="{y}" '
            f'width="{min_box_width}" height="{min_box_height}" />'
        )
        svg_parts.append(
            f'<text class="flow-label" x="{x + min_box_width / 2}" '
            f'y="{y + min_box_height / 2 + 5}">{html.escape(label)}</text>'
        )
    
    # Draw arrows (simple sequential for now)
    for idx in range(len(boxes) - 1):
        col1 = idx % cols
        row1 = idx // cols
        col2 = (idx + 1) % cols
        row2 = (idx + 1) // cols
        
        x1 = padding + col1 * (min_box_width + box_spacing_x) + min_box_width
        y1 = padding + row1 * (min_box_height + box_spacing_y) + min_box_height / 2
        x2 = padding + col2 * (min_box_width + box_spacing_x)
        y2 = padding + row2 * (min_box_height + box_spacing_y) + min_box_height / 2
        
        # Simple straight arrow
        svg_parts.append(
            f'<line class="flow-arrow" x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" />'
        )
    
    svg_parts.append('</svg>')
    return ''.join(svg_parts)


def render_modern_ascii_diagram_v2(lines: list[str], context: str = "") -> str:
    """Enhanced ASCII diagram renderer with smart detection and SVG output.
    
    This function detects the type of ASCII diagram and renders an appropriate
    modern SVG visualization.
    """
    if not lines:
        return ""
    
    # Detect diagram type
    has_bit_markers = any(re.search(r'^\s*\d+(\s+\d+)+\s*$', line.strip()) for line in lines)
    has_flow_elements = any('+' in line and '|' in line for line in lines)
    has_simple_boxes = all(
        not line.strip() or 
        re.search(r'\+[-+]+\+', line) or 
        re.search(r'\|.*\|', line)
        for line in lines
    )
    
    # Try to parse as bit field diagram
    if has_bit_markers or (has_simple_boxes and any('+-+' in line for line in lines)):
        fields = parse_bit_field_diagram(lines)
        if fields:
            return render_bit_field_svg(fields, context)
    
    # Try to parse as flow diagram
    if has_flow_elements:
        flow_data = parse_flow_diagram(lines)
        if flow_data.get('boxes'):
            return render_flow_svg(flow_data, context)
    
    # Fallback: enhanced text representation
    diagram_text = '\n'.join(lines)
    return f'''<div class="modern-diagram-fallback">
<pre style="font-family: 'IBM Plex Mono', monospace; font-size: 0.85em; line-height: 1.5; color: #e2e8f0;">{html.escape(diagram_text)}</pre>
</div>'''


# Export for backward compatibility
render_modern_ascii_diagram = render_modern_ascii_diagram_v2
