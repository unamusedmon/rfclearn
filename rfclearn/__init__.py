"""RFC Learn - A threat hunting reference platform for RFCs.

This package contains the refactored code from build_rfc_collection.py,
split into logical modules for better maintainability.
"""

from .models import RFCMeta, RFCBuild
from .config import (
    ROOT,
    DATA_DIR,
    SITE_DIR,
    EPUB_DIR,
    RFC_BASE,
    RFCS,
    TAG_DESCRIPTIONS,
    STUDY_TRACKS,
    SCIENCE_NOTES,
    HEADER_REFERENCES,
    THREAT_INDICATORS,
    DETECTION_QUESTIONS,
    KNOWN_RFC_TAG_GROUPS,
    KNOWN_RFC_TAGS,
    RELATION_RE,
    RFC_NUM_RE,
)
from .templates import SITE_CSS, INDEX_JS, DOC_JS

__all__ = [
    "RFCMeta",
    "RFCBuild",
    "ROOT",
    "DATA_DIR",
    "SITE_DIR", 
    "EPUB_DIR",
    "RFC_BASE",
]
