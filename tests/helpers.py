import base64
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple

from fastapi.testclient import TestClient
from pydantic.main import BaseModel
from requests.models import Response

from fastapi_cloudauth.base import ScopedAuth, UserInfoAuth


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


def decode_token(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
    header, payload, *rest = token.split(".")

    header += f"{'=' * (len(header) % 4)}"
    payload += f"{'=' * (len(payload) % 4)}"
    _header = json.loads(base64.b64decode(header).decode())
    _payload = json.loads(base64.b64decode(payload).decode())
    return _header, _payload, rest
