import base64
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from pydantic.main import BaseModel
from requests.models import Response

from fastapi_cloudauth.base import ScopedAuth, UserInfoAuth
from fastapi_cloudauth.verification import JWKsVerifier


@dataclass
class Auths:
    protect_auth: ScopedAuth
    protect_auth_ne: ScopedAuth
    ms_auth: UserInfoAuth
    ms_auth_ne: UserInfoAuth
    invalid_ms_auth: UserInfoAuth
    invalid_ms_auth_ne: UserInfoAuth
    valid_claim: BaseModel
    invalid_claim: BaseModel


class BaseTestCloudAuth:
    """
    Required
        setup: initialize test case
        teardown: del items for test
        decode: check decoded token and assigned info
    """

    ACCESS_TOKEN = ""
    SCOPE_ACCESS_TOKEN = ""
    ID_TOKEN = ""
    TESTAUTH: Auths

    def setup(self, scope: Iterable[str]) -> None:
        ...  # pragma: no cover

    def teardown(self) -> None:
        ...  # pragma: no cover

    def decode(self) -> None:
        ...  # pragma: no cover


def assert_get_response(
    client: TestClient, endpoint: str, token: str, status_code: int, detail: str = ""
) -> Response:
    if token:
        headers = {"authorization": f"Bearer {token}"}
    else:
        headers = {}
    response = client.get(endpoint, headers=headers)
    assert response.status_code == status_code, f"{response.json()}"
    if detail:
        assert response.json().get("detail", "") == detail
    return response


def _assert_verifier(token, verifier: JWKsVerifier) -> HTTPException:
    http_auth = HTTPAuthorizationCredentials(scheme="a", credentials=token)
    with pytest.raises(HTTPException) as e:
        verifier._verify_claims(http_auth)
    return e.value


def _assert_verifier_no_error(token, verifier: JWKsVerifier) -> None:
    http_auth = HTTPAuthorizationCredentials(scheme="a", credentials=token)
    assert verifier._verify_claims(http_auth) is False


def decode_token(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
    header, payload, *rest = token.split(".")

    header += f"{'=' * (len(header) % 4)}"
    payload += f"{'=' * (len(payload) % 4)}"
    _header = json.loads(base64.b64decode(header).decode())
    _payload = json.loads(base64.b64decode(payload).decode())
    return _header, _payload, rest
