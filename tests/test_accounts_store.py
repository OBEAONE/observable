import datetime as dt

import pytest

from observable.accounts.store import (
    AccountAlreadyExistsError,
    AccountStore,
    UnknownAccountError,
)
from observable.accounts.totp import totp_now

NOW = dt.datetime(2026, 10, 3, 9, 0, tzinfo=dt.timezone.utc)


def test_store_starts_empty():
    store = AccountStore()
    assert store.is_empty() is True


def test_create_succeeds_once():
    store = AccountStore()
    account = store.create(username="omar", password="hunter2x!", now=NOW)
    assert account.username == "omar"
    assert store.is_empty() is False


def test_create_a_second_time_is_refused():
    store = AccountStore()
    store.create(username="omar", password="hunter2x!", now=NOW)
    with pytest.raises(AccountAlreadyExistsError):
        store.create(username="someone-else", password="another-password", now=NOW)


def test_get_unknown_account_raises():
    store = AccountStore()
    with pytest.raises(UnknownAccountError):
        store.get("does-not-exist")


def test_verify_password_correct_and_incorrect():
    store = AccountStore()
    store.create(username="omar", password="hunter2x!", now=NOW)
    assert store.verify_password("omar", "hunter2x!") is True
    assert store.verify_password("omar", "wrong") is False


def test_verify_password_for_unknown_username_is_false_not_an_exception():
    # No account exists yet -- this must fail closed (False), not raise,
    # so a login handler can treat "no such user" and "wrong password"
    # identically without a try/except for the lookup case.
    store = AccountStore()
    assert store.verify_password("nobody", "whatever") is False


def test_verify_totp_correct_and_incorrect():
    store = AccountStore()
    account = store.create(username="omar", password="hunter2x!", now=NOW)
    good_code = totp_now(account.totp_secret, now=NOW.timestamp())
    assert store.verify_totp("omar", good_code, now=NOW) is True
    assert store.verify_totp("omar", "000000", now=NOW) is False
