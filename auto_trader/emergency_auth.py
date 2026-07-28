from __future__ import annotations

import hashlib
import re


SIMULATED_EMERGENCY_AUTHENTICATION_KEY = hashlib.sha256(
    b"quant-auto-trader-simulation-emergency-journal-v1"
).hexdigest()

_KEY_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def decode_emergency_authentication_key(value: str) -> bytes:
    normalized = str(value).strip()
    if not _KEY_PATTERN.fullmatch(normalized):
        raise ValueError(
            "EMERGENCY_AUTHENTICATION_KEY must be exactly 64 lowercase hexadecimal "
            "characters."
        )
    return bytes.fromhex(normalized)


def emergency_authentication_key_fingerprint(value: str) -> str:
    return hashlib.sha256(decode_emergency_authentication_key(value)).hexdigest()


def is_strong_emergency_authentication_key(value: str) -> bool:
    try:
        key = decode_emergency_authentication_key(value)
    except ValueError:
        return False
    if str(value).strip() == SIMULATED_EMERGENCY_AUTHENTICATION_KEY:
        return False
    # Reject obvious placeholders while retaining all ordinary 256-bit random keys.
    return len(set(key)) >= 8
