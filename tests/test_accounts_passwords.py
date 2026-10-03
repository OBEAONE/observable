from observable.accounts.passwords import hash_password


def test_correct_password_verifies():
    h = hash_password("correct horse battery staple")
    assert h.verify("correct horse battery staple") is True


def test_wrong_password_is_rejected():
    h = hash_password("correct horse battery staple")
    assert h.verify("wrong password") is False


def test_same_password_hashed_twice_produces_different_salts_and_digests():
    # Random salt per hash -- two operators who happen to pick the same
    # password must not end up with identical stored hashes.
    a = hash_password("same-password")
    b = hash_password("same-password")
    assert a.salt != b.salt
    assert a.digest != b.digest
    # but both still verify correctly against their own hash
    assert a.verify("same-password") is True
    assert b.verify("same-password") is True


def test_plaintext_password_is_never_present_in_the_stored_hash():
    password = "my-unique-plaintext-marker-xyz"
    h = hash_password(password)
    assert password.encode("utf-8") not in h.digest
    assert password.encode("utf-8") not in h.salt
