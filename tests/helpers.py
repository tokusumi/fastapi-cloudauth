import json
import base64


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
    TESTCLIENT = None


def assert_get_response(client, endpoint, token, status_code, detail=""):
    if token:
        headers = {"authorization": f"Bearer {token}"}
    else:
        headers = {}
    response = client.get(endpoint, headers=headers)
    assert response.status_code == status_code, f"{response.json()}"
    if detail:
        assert response.json().get("detail", "") == detail
    return response


def decode_token(token):
    header, payload, *rest = token.split(".")

    header += f"{'=' * (len(header) % 4)}"
    payload += f"{'=' * (len(payload) % 4)}"
    header = json.loads(base64.b64decode(header).decode())
    payload = json.loads(base64.b64decode(payload).decode())
    return header, payload, rest
