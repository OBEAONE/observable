"""
Block 6 — Agent-side SDK.

What an agent process actually imports: generate its own keypair
(private key never leaves the process), enroll once, then request
tokens and call the gateway. Every request is signed with the agent's
private key per observable.api.pop, so the SDK is also the reference
implementation of the client half of that proof-of-possession scheme.

Works against any object exposing an httpx-compatible ``.post``/``.get``
(a real ``httpx.Client``, or Starlette's ``TestClient`` for in-process
demos and tests).
"""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import json
import uuid
from typing import Any, Optional, Protocol

from cryptography.hazmat.primitives.asymmetric import ec

from observable.api.pop import sign_request
from observable.pki.reference_ca import ReferenceCA


class HttpClient(Protocol):
    def post(self, url: str, *, content: bytes, headers: dict) -> Any: ...
    def get(self, url: str, *, headers: Optional[dict] = None) -> Any: ...


class AgentClientError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(f"HTTP {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


def _raise_for_status(response) -> None:
    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", response.text)
        except Exception:  # noqa: BLE001
            detail = response.text
        raise AgentClientError(response.status_code, detail)


@dataclasses.dataclass
class AgentClient:
    http: HttpClient
    private_key: ec.EllipticCurvePrivateKey
    certificate_pem: bytes
    agent_id: str

    # ------------------------------------------------------------------
    @classmethod
    def enroll(
        cls,
        *,
        http: HttpClient,
        display_name: str,
        role: str,
        tier: str,
        enrolled_by: str,
    ) -> "AgentClient":
        private_pem, public_pem = ReferenceCA.generate_keypair()
        from cryptography.hazmat.primitives import serialization

        private_key = serialization.load_pem_private_key(private_pem, password=None)

        body = json.dumps(
            {
                "display_name": display_name,
                "role": role,
                "tier": tier,
                "public_key_pem": public_pem.decode("utf-8"),
                "enrolled_by": enrolled_by,
            }
        ).encode("utf-8")

        response = http.post(
            "/enroll", content=body, headers={"Content-Type": "application/json"}
        )
        _raise_for_status(response)
        data = response.json()

        return cls(
            http=http,
            private_key=private_key,
            certificate_pem=data["certificate_pem"].encode("utf-8"),
            agent_id=data["agent_id"],
        )

    # ------------------------------------------------------------------
    def _signed_post(self, path: str, body_obj: dict) -> Any:
        body = json.dumps(body_obj).encode("utf-8")
        timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
        nonce = uuid.uuid4().hex
        signature = sign_request(
            private_key=self.private_key,
            method="POST",
            path=path,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        headers = {
            "Content-Type": "application/json",
            "X-Observable-Client-Cert": base64.b64encode(self.certificate_pem).decode("ascii"),
            "X-Observable-Timestamp": timestamp,
            "X-Observable-Nonce": nonce,
            "X-Observable-Signature": base64.b64encode(signature).decode("ascii"),
        }
        response = self.http.post(path, content=body, headers=headers)
        _raise_for_status(response)
        return response.json()

    # ------------------------------------------------------------------
    def request_token(
        self, scopes: list[str], *, purpose: Optional[str] = None, risk_score: float = 0.0
    ) -> str:
        data = self._signed_post(
            "/token",
            {"requested_scopes": scopes, "purpose": purpose, "risk_score": risk_score},
        )
        return data["access_token"]

    def invoke(
        self, token: str, *, tool_name: str, payload: dict, resource_id: Optional[str] = None
    ) -> dict:
        body = json.dumps({"tool_name": tool_name, "payload": payload, "resource_id": resource_id}).encode(
            "utf-8"
        )
        timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
        nonce = uuid.uuid4().hex
        signature = sign_request(
            private_key=self.private_key,
            method="POST",
            path="/gateway/invoke",
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "X-Observable-Client-Cert": base64.b64encode(self.certificate_pem).decode("ascii"),
            "X-Observable-Timestamp": timestamp,
            "X-Observable-Nonce": nonce,
            "X-Observable-Signature": base64.b64encode(signature).decode("ascii"),
        }
        response = self.http.post("/gateway/invoke", content=body, headers=headers)
        _raise_for_status(response)
        return response.json()
