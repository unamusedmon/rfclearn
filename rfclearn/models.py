"""Data models for RFC Learn."""

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class RFCMeta:
    """Metadata about an RFC."""
    num: int
    title: str
    relevance: str
    tags: tuple[str, ...]
    keywords: tuple[str, ...] = ()
    update_chain: bool = False


@dataclass
class RFCBuild:
    """Build information for an RFC."""
    meta: RFCMeta
    text_path: Path | None = None
    html_path: Path | None = None
    text_ok: bool = False
    html_ok: bool = False
    text_error: str | None = None
    html_error: str | None = None
    depth: int = 0
