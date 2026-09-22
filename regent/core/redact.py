"""Redaction before anything is written to the chain or shipped as evidence.

Books-and-records rules want the *fact* of a blocked NPI egress, not a second
copy of the NPI. We keep the structure and hash of the redacted value so an
examiner can confirm the same payload was seen twice without seeing it.
"""
from __future__ import annotations

import re
from typing import Any

from regent.core.match import PII_PATTERNS
from regent.core.models import sha256_hex

REDACT_KINDS = ("ssn", "account_number", "credit_card", "routing_number", "dob", "email", "phone", "npi", "mrn")
SENSITIVE_KEYS = re.compile(r"(password|secret|token|api[_-]?key|authorization|cookie|ssn|tax_id|dob)", re.I)
MAX_STRING = 512


def redact_text(text: str, kinds: tuple[str, ...] = REDACT_KINDS) -> tuple[str, list[str]]:
    found: list[str] = []
    out = text
    for kind in kinds:
        pat = PII_PATTERNS[kind]
        if pat.search(out):
            found.append(kind)
            out = pat.sub(f"[REDACTED:{kind.upper()}]", out)
    return out, found


def redact(obj: Any, _key: str | None = None) -> Any:
    """Deep-redact a JSON-like structure. Returns a new structure."""
    if isinstance(obj, dict):
        return {k: redact(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, _key) for v in obj]
    if isinstance(obj, str):
        if _key and SENSITIVE_KEYS.search(_key):
            return {"redacted": True, "sha256": sha256_hex(obj), "len": len(obj)}
        text, found = redact_text(obj)
        if found:
            return {"redacted": True, "kinds": found, "sha256": sha256_hex(obj), "text": text[:MAX_STRING]}
        if len(text) > MAX_STRING:
            return {"truncated": True, "sha256": sha256_hex(obj), "len": len(obj), "text": text[:MAX_STRING]}
        return text
    return obj
