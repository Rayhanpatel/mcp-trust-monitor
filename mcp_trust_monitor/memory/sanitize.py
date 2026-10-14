"""Bounded operator-authored summaries, not a claim of injection immunity."""
from __future__ import annotations

import hashlib
import re
import unicodedata

from .types import MemoryIntegrityError

MAX_SUMMARY_CHARS = 2000
MAX_BODY_CHARS = 8192


def body_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def bounded_text(value: str, name: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise MemoryIntegrityError(f"{name} must be nonempty text of at most {limit} characters")
    if any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value):
        raise MemoryIntegrityError(f"{name} contains control or invisible characters")
    return value


def sanitize_summary(text: str) -> str:
    bounded_text(text, "summary", MAX_SUMMARY_CHARS)
    patterns = (
        r"https?://|www\.|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
        r"(?i)\b(?:sk|ghp|gho|AKIA)[-_A-Za-z0-9]{12,}\b|-----BEGIN.*PRIVATE KEY",
        r"(?i)\b(?:api[_ -]?key|password|secret|token)\s*[:=]\s*\S+",
        r"[A-Za-z0-9+/=_-]{48,}",
        r"(?i)</?(?:system|assistant|user|untrusted|policy|precedent)[^>]*>|<\||\|>",
        r"(?i)\b(?:approve|recommend)\b|\byou\s+(?:must|should|will|are)\b",
        r"(?i)(?:^|[.!?]\s*)(?:ignore|disregard|override|bypass|follow|act|output|return|treat|do)\b",
    )
    if any(re.search(pattern, text) for pattern in patterns):
        raise MemoryIntegrityError("summary contains an unsafe directive, address, role marker or secret-like value")
    return text


def normalize_passage(text: str) -> str:
    return " ".join(text.split())
