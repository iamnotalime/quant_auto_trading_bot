from __future__ import annotations

import hashlib
import re


# This deterministic key exists only so offline simulation remains zero-configuration.
# Alpaca configuration rejects it, including plan-only and emergency processes.
SIMULATED_PLAN_AUTHENTICATION_KEY = hashlib.sha256(
    b"quant-auto-trader-insecure-simulation-plan-authentication-key"
).hexdigest()

_PLAN_AUTHENTICATION_KEY_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def decode_plan_authentication_key(value: str) -> bytes:
    normalized = str(value or "").strip()
    if not _PLAN_AUTHENTICATION_KEY_PATTERN.fullmatch(normalized):
        raise ValueError(
            "PLAN_AUTHENTICATION_KEY must be exactly 64 lowercase hexadecimal characters."
        )
    return bytes.fromhex(normalized)


def plan_authentication_key_fingerprint(value: str) -> str:
    return hashlib.sha256(decode_plan_authentication_key(value)).hexdigest()


def is_strong_plan_authentication_key(value: str) -> bool:
    """Reject the development key and conspicuously low-entropy 256-bit encodings."""

    try:
        key = decode_plan_authentication_key(value)
    except ValueError:
        return False
    if value == SIMULATED_PLAN_AUTHENTICATION_KEY:
        return False
    # Entropy cannot be proven from one sample. This catches common placeholders and
    # repeated-byte secrets while deployment guidance requires a CSPRNG-generated key.
    return len(set(key)) >= 8
