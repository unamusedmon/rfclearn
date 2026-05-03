#!/usr/bin/env python3
"""Build a local RFC threat-hunting reference site and EPUB collection.

Now includes enhanced SVG diagram rendering AND reader UX upgrades.
"""

# Install upgrades before importing builder symbols
import rfclearn.builder as _builder
from rfclearn.diagram_upgrade import install_diagram_upgrade
from rfclearn.reader_upgrade import install_reader_upgrade

install_diagram_upgrade(_builder)
install_reader_upgrade(_builder)

# Re-export original API
from rfclearn.builder import *

if __name__ == "__main__":
    raise SystemExit(main())
