"""
Block 12c — operator account store (§9.11).

A deliberately small, separate identity system from
``observable.identity.registry`` (which issues cryptographic identity to
AI *agents*). This one is for the humans operating Observable itself --
whoever logs into the console. The two are not related, should not be
confused, and are never cross-checked against each other: an operator
account proves a human can see the console; an agent certificate proves
an AI agent can call the Gateway.

Single-operator reference scope, deliberately: there is exactly one way
to create an account (``create``, usable once, while the store is
empty -- "first operator becomes the operator"), not an open
registration flow or a multi-account admin panel. See "What v1.11 does
*not* do" in ARCHITECTURE.md §9.11 for what a real multi-operator
deployment would still need (roles, invitation flow, password reset).
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import threading
from typing import Optional

from observable.accounts.passwords import PasswordHash, hash_password
from observable.accounts.totp import generate_secret, verify_totp


class AccountError(Exception):
    pass


class AccountAlreadyExistsError(AccountError):
    """Raised by ``create`` once an account already exists -- this
    store is single-operator by design (see module docstring)."""


class UnknownAccountError(AccountError):
    pass


@dataclasses.dataclass(frozen=True)
class OperatorAccount:
    username: str
    password_hash: PasswordHash
    totp_secret: str
    created_at: dt.datetime


class AccountStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._accounts: dict[str, OperatorAccount] = {}

    def is_empty(self) -> bool:
        with self._lock:
            return not self._accounts

    def create(self, *, username: str, password: str, now: Optional[dt.datetime] = None) -> OperatorAccount:
        """Create the one operator account this store will ever hold.
        Raises ``AccountAlreadyExistsError`` if a setup has already run
        -- ``POST /accounts/setup`` relies on exactly this to make
        itself a one-time bootstrap rather than an open endpoint
        anyone could call to create more accounts."""
        now = now or dt.datetime.now(dt.timezone.utc)
        with self._lock:
            if self._accounts:
                raise AccountAlreadyExistsError("an operator account already exists")
            account = OperatorAccount(
                username=username,
                password_hash=hash_password(password),
                totp_secret=generate_secret(),
                created_at=now,
            )
            self._accounts[username] = account
            return account

    def get(self, username: str) -> OperatorAccount:
        with self._lock:
            account = self._accounts.get(username)
        if account is None:
            raise UnknownAccountError(f"no such operator account: {username!r}")
        return account

    def verify_password(self, username: str, password: str) -> bool:
        try:
            account = self.get(username)
        except UnknownAccountError:
            # Still run a hash comparison against a throwaway value so a
            # nonexistent username doesn't return measurably faster than
            # a wrong password for a real one (a basic defense against
            # using response timing to enumerate valid usernames).
            hash_password(password)
            return False
        return account.password_hash.verify(password)

    def verify_totp(self, username: str, code: str, *, now: Optional[dt.datetime] = None) -> bool:
        account = self.get(username)  # raises UnknownAccountError if not found
        now_ts = (now or dt.datetime.now(dt.timezone.utc)).timestamp()
        return verify_totp(account.totp_secret, code, now=now_ts)
