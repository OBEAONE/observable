import pytest
from starlette.testclient import TestClient

from observable.accounts.totp import totp_now
from observable.api.app import app, get_state
from observable.api.state import build_default_state


@pytest.fixture()
def client():
    fresh_state = build_default_state()
    app.dependency_overrides[get_state] = lambda: fresh_state
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _setup(client, username="omar", password="correct horse battery staple"):
    resp = client.post("/accounts/setup", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_login_page_served(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "Sign in" in resp.text


def test_setup_returns_totp_secret_and_provisioning_uri(client):
    data = _setup(client)
    assert data["username"] == "omar"
    assert len(data["totp_secret"]) >= 16
    assert data["provisioning_uri"].startswith("otpauth://totp/")
    assert data["totp_secret"] in data["provisioning_uri"]


def test_setup_can_only_run_once(client):
    _setup(client, "omar", "first-password")
    resp = client.post("/accounts/setup", json={"username": "someone-else", "password": "second-password"})
    assert resp.status_code == 409


def test_full_login_flow_allows_console_access(client):
    data = _setup(client, "omar", "correct horse battery staple")
    step1 = client.post("/login/password", json={"username": "omar", "password": "correct horse battery staple"})
    assert step1.status_code == 200
    assert step1.json()["mfa_required"] is True
    assert "observable_mfa" in client.cookies

    code = totp_now(data["totp_secret"])
    step2 = client.post("/login/verify", json={"code": code})
    assert step2.status_code == 200
    assert step2.json() == {"ok": True, "username": "omar"}
    assert "observable_session" in client.cookies

    console = client.get("/console")
    assert console.status_code == 200
    assert "Observable Console" in console.text


def test_wrong_password_is_rejected(client):
    _setup(client, "omar", "correct horse battery staple")
    resp = client.post("/login/password", json={"username": "omar", "password": "wrong"})
    assert resp.status_code == 401
    assert "observable_mfa" not in client.cookies


def test_unknown_username_is_rejected_with_the_same_generic_error(client):
    _setup(client, "omar", "correct horse battery staple")
    resp = client.post("/login/password", json={"username": "nobody", "password": "whatever"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid username or password"


def test_wrong_totp_code_is_rejected_and_no_session_is_issued(client):
    _setup(client, "omar", "correct horse battery staple")
    client.post("/login/password", json={"username": "omar", "password": "correct horse battery staple"})
    resp = client.post("/login/verify", json={"code": "000000"})
    assert resp.status_code == 401
    assert "observable_session" not in client.cookies
    # the pending-MFA attempt is still live -- a wrong code doesn't burn
    # the one chance to complete this login
    assert "observable_mfa" in client.cookies


def test_verify_without_a_completed_password_step_is_rejected(client):
    _setup(client, "omar", "correct horse battery staple")
    resp = client.post("/login/verify", json={"code": "123456"})
    assert resp.status_code == 401
    assert "no pending login" in resp.json()["detail"]


def test_console_denied_after_password_step_alone_without_2fa(client):
    data = _setup(client, "omar", "correct horse battery staple")
    client.post("/login/password", json={"username": "omar", "password": "correct horse battery staple"})
    # 2FA never completed -- no session cookie exists yet
    resp = client.get("/console", follow_redirects=False)
    assert resp.status_code == 303


def test_brute_force_password_guessing_is_throttled(client):
    _setup(client, "omar", "correct horse battery staple")
    for _ in range(5):
        resp = client.post("/login/password", json={"username": "omar", "password": "wrong"})
        assert resp.status_code == 401
    too_many = client.post("/login/password", json={"username": "omar", "password": "wrong"})
    assert too_many.status_code == 429

    # even the *correct* password is throttled now -- the limit is on
    # attempts, not on wrong attempts specifically
    correct_but_throttled = client.post(
        "/login/password", json={"username": "omar", "password": "correct horse battery staple"}
    )
    assert correct_but_throttled.status_code == 429


def test_login_throttling_is_independent_per_username(client):
    _setup(client, "omar", "correct horse battery staple")
    for _ in range(5):
        client.post("/login/password", json={"username": "omar", "password": "wrong"})
    # a different (nonexistent) username is not caught by omar's throttle
    other = client.post("/login/password", json={"username": "someone-else", "password": "whatever"})
    assert other.status_code == 401  # rejected for being wrong, not 429 for being throttled


def test_logout_revokes_the_session(client):
    data = _setup(client, "omar", "correct horse battery staple")
    client.post("/login/password", json={"username": "omar", "password": "correct horse battery staple"})
    client.post("/login/verify", json={"code": totp_now(data["totp_secret"])})
    assert client.get("/console").status_code == 200

    logout = client.post("/logout")
    assert logout.status_code == 200

    after_logout = client.get("/console", follow_redirects=False)
    assert after_logout.status_code == 303


def test_landing_page_sign_in_link_points_to_login(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert 'href="/login"' in resp.text
