"""
Block 12d — opaque token stores for the login flow (§9.11).

Two uses of the exact same shape -- an opaque, unguessable token mapped
to a small payload with an expiry -- so one class (``TokenStore``)
serves both:

- a short-lived "pending MFA" token, issued the moment a password
  check succeeds, naming which username is mid-login and expiring in
  minutes if the 2FA step is never completed;
- a longer-lived session token, issued once the 2FA code checks out,
  naming the logged-in username and expiring after a working day.

Same durability model as every other in-memory store in this codebase
(Elevation Store, Rate Limiter): process-local, reset on restart. For
an operator console that's the safe failure direction -- a restart logs
everyone out rather than leaving a session valid somewhere it can no
longer be revoked from.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import secrets
import threading
from typing import Generic, Optional, TypeVar

T = TypeVar("T")


@dataclasses.dataclass(frozen=True)
class _Entry(Generic[T]):
    payload: T
    expires_at: dt.datetime


class TokenStore(Generic[T]):
    def __init__(self, *, default_ttl: dt.timedelta) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry[T]] = {}
        self._default_ttl = default_ttl

    def issue(self, payload: T, *, ttl: Optional[dt.timedelta] = None, now: Optional[dt.datetime] = None) -> str:
        now = now or dt.datetime.now(dt.timezone.utc)
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._entries[token] = _Entry(payload=payload, expires_at=now + (ttl or self._default_ttl))
        return token

    def get(self, token: str, *, now: Optional[dt.datetime] = None) -> Optional[T]:
        """The token's payload if it exists and hasn't expired, else
        ``None`` -- a missing cookie, a garbage value, and an expired
        token are all the same "not logged in" outcome to a caller,
        exactly like an expired or revoked agent certificate is just
        "not currently valid" to Token Service."""
        now = now or dt.datetime.now(dt.timezone.utc)
        with self._lock:
            entry = self._entries.get(token)
            if entry is None:
                return None
            if entry.expires_at <= now:
                del self._entries[token]
                return None
            return entry.payload

    def revoke(self, token: str) -> None:
        with self._lock:
            self._entries.pop(token, None)
