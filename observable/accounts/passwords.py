"""
Block 12b — password hashing for human-operator accounts (§9.11).

PBKDF2-HMAC-SHA256, from the standard library's ``hashlib`` --
deliberately not a plaintext or a fast unsalted hash, and deliberately
not a new third-party dependency (bcrypt/argon2) for a reference
deployment: PBKDF2 is NIST-recommended, built into Python, and the
iteration count is easy to read and reason about. A production
deployment protecting real operator credentials at scale should prefer
argon2id; swapping the implementation here is a one-file change because
callers only ever go through ``hash_password``/``verify_password``.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import os

DEFAULT_ITERATIONS = 390_000  # OWASP's 2023 minimum recommendation for PBKDF2-HMAC-SHA256
_SALT_BYTES = 16


@dataclasses.dataclass(frozen=True)
class PasswordHash:
    """Everything needed to verify a password later, and nothing else
    -- the plaintext password itself is never stored anywhere."""

    salt: bytes
    digest: bytes
    iterations: int

    def verify(self, password: str) -> bool:
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), self.salt, self.iterations)
        # Constant-time comparison -- a password digest is exactly the
        # kind of secret-derived value a timing side-channel can leak,
        # the same reasoning applied to every other comparison in this
        # codebase involving credentials (PoP signatures, TOTP codes).
        return hmac.compare_digest(candidate, self.digest)


def hash_password(password: str, *, iterations: int = DEFAULT_ITERATIONS) -> PasswordHash:
    salt = os.urandom(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return PasswordHash(salt=salt, digest=digest, iterations=iterations)
