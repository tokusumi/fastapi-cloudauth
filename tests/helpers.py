import base64
import json
from typing import Any, Dict, List, Tuple

from fastapi.testclient import TestClient
from requests.models import Response


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
    TESTCLIENT: TestClient = None

    def setup(self) -> None:
        ...

    def teardown(self) -> None:
        ...

    def decode(self) -> None:
        ...


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
