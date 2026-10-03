from observable.accounts.totp import (
    DEFAULT_STEP_SECONDS,
    generate_secret,
    provisioning_uri,
    totp_now,
    verify_totp,
)

T0 = 1_700_000_000.0  # arbitrary fixed instant, for determinism


def test_generate_secret_is_base32_and_varies():
    a = generate_secret()
    b = generate_secret()
    assert a != b
    assert all(c.isalnum() for c in a)


def test_correct_code_verifies():
    secret = generate_secret()
    code = totp_now(secret, now=T0)
    assert verify_totp(secret, code, now=T0) is True


def test_wrong_code_is_rejected():
    secret = generate_secret()
    assert verify_totp(secret, "000000", now=T0) is False


def test_different_secrets_produce_different_codes():
    a, b = generate_secret(), generate_secret()
    assert totp_now(a, now=T0) != totp_now(b, now=T0)


def test_code_from_one_step_later_is_accepted_within_the_drift_window():
    secret = generate_secret()
    later_code = totp_now(secret, now=T0 + DEFAULT_STEP_SECONDS)
    assert verify_totp(secret, later_code, now=T0, window=1) is True


def test_code_far_outside_the_drift_window_is_rejected():
    secret = generate_secret()
    far_future_code = totp_now(secret, now=T0 + 10 * DEFAULT_STEP_SECONDS)
    assert verify_totp(secret, far_future_code, now=T0, window=1) is False


def test_non_numeric_or_wrong_length_code_is_rejected_without_crashing():
    secret = generate_secret()
    assert verify_totp(secret, "abcdef", now=T0) is False
    assert verify_totp(secret, "123", now=T0) is False
    assert verify_totp(secret, "", now=T0) is False


def test_code_is_stable_within_the_same_time_step():
    secret = generate_secret()
    assert totp_now(secret, now=T0) == totp_now(secret, now=T0 + 5)


def test_code_changes_across_a_step_boundary():
    secret = generate_secret()
    assert totp_now(secret, now=T0) != totp_now(secret, now=T0 + DEFAULT_STEP_SECONDS)


def test_provisioning_uri_contains_secret_and_issuer():
    secret = generate_secret()
    uri = provisioning_uri(secret, account_name="omar", issuer="Observable")
    assert uri.startswith("otpauth://totp/")
    assert secret in uri
    assert "issuer=Observable" in uri
