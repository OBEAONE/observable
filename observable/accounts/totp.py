"""
Block 12a — TOTP (RFC 6238), for human-operator 2FA (§9.11).

Everything else cryptographic in this codebase (certificates, PoP
signatures, the audit chain) is already hand-rolled on top of the
`cryptography` library rather than delegated to a framework that hides
the mechanism — this follows the same spirit for the one new primitive
operator login needs. TOTP is a small, standard, stdlib-only
computation (HMAC-SHA1 over a moving time counter, RFC 6238 on top of
HOTP, RFC 4226), so it's implemented directly here rather than pulling
in a new third-party dependency for ~40 lines of well-specified code.
Interoperable with any standard authenticator app (Google Authenticator,
Authy, 1Password, etc.) via the `otpauth://` provisioning URI.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
import urllib.parse

DEFAULT_STEP_SECONDS = 30
DEFAULT_DIGITS = 6
# How many time-steps of drift either side of "now" to accept when
# verifying -- a small window tolerates the authenticator app's clock
# (or the verifier's) being a few seconds to a minute off, without
# materially weakening the code's effective lifetime.
DEFAULT_WINDOW = 1


def generate_secret(length: int = 20) -> str:
    """A fresh random TOTP secret, Base32-encoded (the form every
    authenticator app expects to scan or type in). 20 raw bytes (160
    bits) matches the RFC 4226 recommendation for HMAC-SHA1-based
    HOTP/TOTP keys."""
    return base64.b32encode(os.urandom(length)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int, *, digits: int = DEFAULT_DIGITS) -> str:
    """RFC 4226 HOTP: one counter-based one-time code. TOTP (below) is
    just HOTP with the counter derived from the current time instead of
    an explicit increment."""
    # Base32 requires padding to a multiple of 8 chars to decode.
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = truncated % (10**digits)
    return str(code).zfill(digits)


def totp_now(
    secret_b32: str, *, now: float | None = None, step: int = DEFAULT_STEP_SECONDS, digits: int = DEFAULT_DIGITS
) -> str:
    """The current valid code for ``secret_b32``. Mainly for tests and
    for showing an operator what code to expect; real verification
    should go through ``verify_totp`` (which tolerates a little clock
    drift), not an exact match against this."""
    now = time.time() if now is None else now
    counter = int(now // step)
    return _hotp(secret_b32, counter, digits=digits)


def verify_totp(
    secret_b32: str,
    code: str,
    *,
    now: float | None = None,
    step: int = DEFAULT_STEP_SECONDS,
    digits: int = DEFAULT_DIGITS,
    window: int = DEFAULT_WINDOW,
) -> bool:
    """True if ``code`` matches the TOTP for ``secret_b32`` at ``now``
    (default: the real clock), or at any of the ``window`` time-steps
    immediately before/after it. Constant-time comparison
    (``hmac.compare_digest``) per code candidate, same reasoning as
    comparing a password hash or a signature -- a code is a secret-derived
    value, so a timing side-channel on the comparison is a real attack
    surface, not a theoretical one."""
    now = time.time() if now is None else now
    code = code.strip()
    if not code.isdigit() or len(code) != digits:
        return False
    counter = int(now // step)
    for offset in range(-window, window + 1):
        candidate = _hotp(secret_b32, counter + offset, digits=digits)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def provisioning_uri(
    secret_b32: str,
    *,
    account_name: str,
    issuer: str = "Observable",
    step: int = DEFAULT_STEP_SECONDS,
    digits: int = DEFAULT_DIGITS,
) -> str:
    """The ``otpauth://totp/...`` URI standard authenticator apps accept
    (scanned as a QR code, or pasted directly -- this reference
    deployment has no QR-image generation, so the setup response
    returns this URI as text; any authenticator app can add an account
    from the URI/secret directly without a QR code)."""
    label = urllib.parse.quote(f"{issuer}:{account_name}")
    params = urllib.parse.urlencode(
        {"secret": secret_b32, "issuer": issuer, "algorithm": "SHA1", "digits": digits, "period": step}
    )
    return f"otpauth://totp/{label}?{params}"
