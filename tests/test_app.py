"""End-to-end tests of the flasgo DBSC probe: offer -> register -> refresh -> gate -> restart."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from dbsc import Binding, CorruptStateError, InMemoryStore

from dbsc_probe.app import COOKIE_NAME, ProbeApp, create_app

_ORIGIN = "http://localhost"
_CHALLENGE_PARAM = re.compile(r'"([^"]+)"')

COOKIES_EXCLUDE = {"flasgo-session", "flasgo-csrf"}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign(key: ec.EllipticCurvePrivateKey, signing_input: str) -> str:
    der = key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _compact_jwt(
    header: dict[str, Any], payload: dict[str, Any], key: ec.EllipticCurvePrivateKey
) -> str:
    signing_input = ".".join(
        _b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, payload)
    )
    return f"{signing_input}.{_sign(key, signing_input)}"


def _registration_jwt(challenge: str, key: ec.EllipticCurvePrivateKey) -> str:
    numbers = key.public_key().public_numbers()
    header = {
        "alg": "ES256",
        "typ": "dbsc+credential",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(numbers.x.to_bytes(32, "big")),
            "y": _b64url(numbers.y.to_bytes(32, "big")),
        },
    }
    return _compact_jwt(header, {"jti": challenge}, key)


def _refresh_jwt(challenge: str, key: ec.EllipticCurvePrivateKey) -> str:
    return _compact_jwt({"alg": "ES256", "typ": "dbsc+refresh"}, {"jti": challenge}, key)


def _quoted_param(header_value: str) -> str:
    match = _CHALLENGE_PARAM.search(header_value)
    if match is None:
        raise AssertionError(f"no quoted value in {header_value!r}")
    return match.group(1)


def _challenge(reg_header: str) -> str:
    match = re.search(r'challenge="([^"]+)"', reg_header)
    if match is None:
        raise AssertionError(f"no challenge in {reg_header!r}")
    return match.group(1)


@pytest.fixture
def client() -> Any:
    return create_app().test_client()


class _CorruptStore(InMemoryStore):
    """A store whose binding reads fail closed, as a corrupt record would."""

    async def get_binding(self, session_id: str) -> Binding | None:  # noqa: ARG002
        raise CorruptStateError("unreadable record")


@pytest.fixture
def device_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _set_cookie(client: Any, name: str) -> str | None:
    return client.cookies.get(name)


def _register(client: Any, key: ec.EllipticCurvePrivateKey) -> str:
    page = client.get("/")
    reg_header = page.headers["secure-session-registration"]
    challenge = _challenge(reg_header)
    response = client.post(
        "/dbsc/register",
        headers={"sec-session-response": _registration_jwt(challenge, key)},
    )
    assert response.status_code == 200
    assert _set_cookie(client, COOKIE_NAME) is not None
    assert response.headers["sec-secure-session-id"]
    return challenge


def test_page_offers_registration(client: Any) -> None:
    page = client.get("/")
    assert page.status_code == 200
    assert "DBSC probe" in page.text
    reg_header = page.headers["secure-session-registration"]
    assert "/dbsc/register" in reg_header
    assert _challenge(reg_header)

    status = client.get("/status").json()
    assert status["registered"] is False
    assert status["probe"]
    assert status["origin"] == _ORIGIN
    assert status["registration_header"] == reg_header
    assert status["registration_jwt"] is None

    for name in page.headers:
        assert name == name.lower()
    assert page.headers["content-security-policy"].startswith("default-src 'self'")
    assert "no-store" in page.headers["cache-control"]


def test_register_unbinds_then_binds(client: Any, device_key: ec.EllipticCurvePrivateKey) -> None:
    page = client.get("/")
    challenge = _challenge(page.headers["secure-session-registration"])

    mismatched = client.post(
        "/dbsc/register",
        headers={"sec-session-response": _registration_jwt("not-the-challenge", device_key)},
    )
    assert mismatched.status_code == 401

    status = client.get("/status").json()
    assert status["registered"] is False

    registered = client.post(
        "/dbsc/register",
        headers={"sec-session-response": _registration_jwt(challenge, device_key)},
    )
    assert registered.status_code == 200
    assert _set_cookie(client, COOKIE_NAME)

    status = client.get("/status").json()
    assert status["registered"] is True
    binding = status["binding"]
    assert binding is not None
    assert binding["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    assert binding["algorithm"] == "ES256"
    assert binding["session_identifier"]
    assert status["bound_cookie_matches"] is True
    assert status["cookie"]["present"] is True
    assert {entry["event"] for entry in status["timeline"]} >= {"PROBE_STARTED", "dbscRegistered"}
    jwt = status["registration_jwt"]
    assert jwt is not None
    assert jwt["payload"]["jti"] == challenge
    assert jwt["header"]["jwk"]["kty"] == "EC"


def test_register_without_offer_is_rejected(
    client: Any, device_key: ec.EllipticCurvePrivateKey
) -> None:
    response = client.post(
        "/dbsc/register",
        headers={"sec-session-response": _registration_jwt("anything", device_key)},
    )
    assert response.status_code == 401


def test_register_missing_proof_is_400(client: Any) -> None:
    client.get("/")
    response = client.post("/dbsc/register")
    assert response.status_code == 400


def test_refresh_two_phase_rotates_cookie(
    client: Any, device_key: ec.EllipticCurvePrivateKey
) -> None:
    _register(client, device_key)
    before = _set_cookie(client, COOKIE_NAME)
    assert before is not None

    challenged = client.post("/dbsc/refresh")
    assert challenged.status_code == 403
    assert "no-store" in challenged.headers["cache-control"]
    challenge_header = challenged.headers["secure-session-challenge"]
    assert 'id="' in challenge_header
    challenge = _quoted_param(challenge_header)

    refreshed = client.post(
        "/dbsc/refresh",
        headers={"sec-session-response": _refresh_jwt(challenge, device_key)},
    )
    assert refreshed.status_code == 200
    assert refreshed.headers["sec-secure-session-id"]
    after = _set_cookie(client, COOKIE_NAME)
    assert after is not None
    assert after != before

    status = client.get("/status").json()
    assert status["registered"] is True
    assert status["binding"]["has_refreshed"] is True
    assert {entry["event"] for entry in status["timeline"]} >= {"dbscRegistered", "dbscRefreshed"}


def test_refresh_mismatched_proof_is_retryable(
    client: Any, device_key: ec.EllipticCurvePrivateKey
) -> None:
    _register(client, device_key)
    stubborn = client.post(
        "/dbsc/refresh",
        headers={"sec-session-response": _refresh_jwt("bogus-challenge", device_key)},
    )
    assert stubborn.status_code == 403
    assert "secure-session-challenge" in stubborn.headers


def test_check_gate_degraded_then_passes(
    client: Any, device_key: ec.EllipticCurvePrivateKey
) -> None:
    client.get("/")
    degraded = client.get("/check").json()
    assert degraded["registered"] is False
    assert degraded["decision"] == "degraded"

    _register(client, device_key)
    gated = client.get("/check").json()
    assert gated["registered"] is True
    assert gated["cookie_present"] is True
    assert gated["bound_cookie_matches"] is True
    assert gated["decision"] == "pass"


def test_check_gate_fails_closed_when_unreadable() -> None:
    probe = ProbeApp(store=_CorruptStore())
    client = probe.app.test_client()
    status: Any = client.get("/status").json()
    assert status["corrupt"] is True
    assert status["registered"] is False
    check: Any = client.get("/check").json()
    assert check["corrupt"] is True
    assert check["decision"] == "fail_closed"


def test_restart_revokes_and_starts_fresh(
    client: Any, device_key: ec.EllipticCurvePrivateKey
) -> None:
    _register(client, device_key)
    old_probe = client.get("/status").json()["probe"]
    assert client.get("/status").json()["registered"] is True

    restarted = client.post("/restart")
    assert restarted.status_code == 200

    status = client.get("/status").json()
    assert status["registered"] is False
    assert status["probe"] != old_probe
    assert status["timeline"] == []
    assert _set_cookie(client, COOKIE_NAME) is None


def test_static_assets_served(client: Any) -> None:
    assert client.get("/static/probe.css").status_code == 200
    assert client.get("/static/probe.js").status_code == 200
    assert client.get("/favicon.ico").status_code == 204
