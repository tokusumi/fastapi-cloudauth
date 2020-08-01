import os
import requests
from typing import Optional
from jose import jwt
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_cloudauth.auth0 import Auth0, Auth0Claims, Auth0CurrentUser

DOMAIN = os.environ["AUTH0_DOMAIN"]
CLIENTID = os.environ["AUTH0_CLIENTID"]
CLIENT_SECRET = os.environ["AUTH0_CLIENT_SECRET"]
AUDIENCE = os.environ["AUTH0_AUDIENCE"]
CONNECTION = os.environ["AUTH0_CONNECTION"]


def add_test_user(
    username="test_user@example.com", password="testPass1-", scope: Optional[str] = None
):
    resp = requests.post(
        f"https://{DOMAIN}/dbconnections/signup",
        {
            "client_id": CLIENTID,
            "email": username,
            "password": password,
            "connection": CONNECTION,
            "username": username,
        },
    )
    print(resp.json())
    access_token, _ = get_access_token()
    user_id = jwt.get_unverified_claims(access_token)["sub"]
    default_token = get_default_access_token()
    resp = requests.post(
        f"https://{DOMAIN}/api/v2/users/{user_id}/permissions",
        headers={
            "authorization": f"Bearer {default_token}",
            "cache-control": "no-cache",
        },
        data={
            "permissions": [
                {
                    "resource_server_identifier": f"https://{DOMAIN}/api/v2/",
                    "permission_name": scope,
                }
            ]
        },
    )


def get_access_token(
    username="test_user@example.com", password="testPass1-", scope: Optional[str] = None
):
    """
    NOTE: the followings setting in Auth0 dashboard is required
    - sidebar > Applications > settings > Advanced settings > grant: click `password` on
    - top right icon > Set General > API Authorization Settings > Default Directory to Username-Password-Authentication
    NOTE: In Auth0 dashboard, create custom applications and add permission of `read:test` and copy the audience (identifier) in environment variable.
    """
    resp = requests.post(
        f"https://{DOMAIN}/oauth/token",
        headers={"content-type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": CLIENTID,
            "client_secret": CLIENT_SECRET,
            "audience": AUDIENCE,
        },
    )
    access_token = resp.json()["access_token"]
    resp = requests.post(
        f"https://{DOMAIN}/oauth/token",
        headers={"content-type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": CLIENTID,
            "client_secret": CLIENT_SECRET,
        },
    )
    id_token = resp.json()["id_token"]

    return access_token, id_token


def get_default_access_token(
    username="test_user@example.com", password="testPass1-", scope: Optional[str] = None
):
    resp = requests.post(
        f"https://{DOMAIN}/oauth/token",
        headers={"content-type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": CLIENTID,
            "client_secret": CLIENT_SECRET,
            "audience": f"https://{DOMAIN}/api/v2/",
        },
    )
    access_token = resp.json()["access_token"]
    return access_token


scope = "read:test"
add_test_user(scope=scope)
ACCESS_TOKEN, ID_TOKEN = get_access_token()
DEFAULT_ACCESS_TOKEN = get_default_access_token()


app = FastAPI()

auth = Auth0(domain=DOMAIN)
auth_no_error = Auth0(domain=DOMAIN, auto_error=False)
get_current_user = Auth0CurrentUser(domain=DOMAIN)
get_current_user_no_error = Auth0CurrentUser(domain=DOMAIN, auto_error=False)


@app.get("/", dependencies=[Depends(auth)])
async def secure(payload=Depends(auth)) -> bool:
    return payload


@app.get("/no-error/", dependencies=[Depends(auth_no_error)])
async def secure_no_error(payload=Depends(auth_no_error)) -> bool:
    return payload


@app.get("/scope/", dependencies=[Depends(auth.scope(scope))])
async def secure_scope() -> bool:
    pass


@app.get("/scope/no-error/")
async def secure_scope_no_error(payload=Depends(auth_no_error.scope(scope)),):
    assert payload is None


@app.get("/user/", response_model=Auth0Claims)
async def secure_user(current_user: Auth0Claims = Depends(get_current_user)):
    return current_user


@app.get("/user/no-error/")
async def secure_user_no_error(
    current_user: Optional[Auth0Claims] = Depends(get_current_user_no_error),
):
    assert current_user is None


client = TestClient(app)


def test_valid_token():
    response = client.get("/", headers={"authorization": f"Bearer {ACCESS_TOKEN}"})
    assert response.status_code == 200


def test_no_token():
    # handle in fastapi.security.HtTPBearer
    response = client.get("/")
    assert response.status_code == 403


def test_incompatible_kid_token():
    # manipulate header
    token = ACCESS_TOKEN.split(".", 1)[-1]
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIzMDQ5ODE1MWMyMTRiNzg4ZGQ5N2YyMmI4NTQxMGE1In0."
        + token
    )
    response = client.get("/", headers={"authorization": f"Bearer {token}"})
    assert response.status_code == 403, "must not be verified"

    # not auto_error
    response = client.get("/no-error/", headers={"authorization": f"Bearer {token}"},)
    assert response.status_code == 200, "must not be verified"
    assert response.content == b"null"


def test_no_kid_token():
    # manipulate header
    token = ACCESS_TOKEN.split(".", 1)[-1]
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + token
    response = client.get("/", headers={"authorization": f"Bearer {token}"})
    assert response.status_code == 403, "must not be verified"

    # not auto_error
    response = client.get("/no-error/", headers={"authorization": f"Bearer {token}"},)
    assert response.status_code == 200, "must not be verified"
    assert response.content == b"null"


def test_not_verified_token():
    # manipulate public_key
    response = client.get(
        "/", headers={"authorization": f"Bearer {ACCESS_TOKEN}"[:-3] + "aaa"}
    )
    assert response.status_code == 403, "must not be verified"

    # not auto_error
    response = client.get(
        "/no-error/", headers={"authorization": f"Bearer {ACCESS_TOKEN}"[:-3] + "aaa"},
    )
    assert response.status_code == 200, "must not be verified"
    assert response.content == b"null"


def test_valid_scope():
    response = client.get(
        "/scope/", headers={"authorization": f"Bearer {ACCESS_TOKEN}"}
    )
    assert response.status_code == 200, f"{response.json()}"


def test_invalid_scope():
    response = client.get(
        "/scope/", headers={"authorization": f"Bearer {DEFAULT_ACCESS_TOKEN}"}
    )
    assert response.status_code == 403, f"{response.json()}"

    response = client.get(
        "/scope/no-error/", headers={"authorization": f"Bearer {DEFAULT_ACCESS_TOKEN}"}
    )
    assert response.status_code == 200, f"{response.json()}"


def test_get_current_user():
    response = client.get("/user/", headers={"authorization": f"Bearer {ID_TOKEN}"})
    assert response.status_code == 200, f"{response.json()}"
    for value in response.json().values():
        assert value, f"{response.content} failed to parse"


def test_not_verified_user_no_error():
    response = client.get(
        "/user/no-error/", headers={"authorization": f"Bearer {ID_TOKEN}"[:-3] + "aaa"},
    )
    assert response.status_code == 200, f"{response.json()}"


def test_insufficient_current_user_info():
    response = client.get("/user/", headers={"authorization": f"Bearer {ACCESS_TOKEN}"})
    assert response.status_code == 403, f"{response.json()}"


def test_insufficient_current_user_info_no_error():
    response = client.get(
        "/user/no-error/", headers={"authorization": f"Bearer {ACCESS_TOKEN}"}
    )
    assert response.status_code == 200, f"{response.json()}"
