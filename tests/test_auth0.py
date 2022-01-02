import os
from datetime import datetime, timedelta
from sys import version_info as info
from typing import Iterable, List, Optional

import pytest
import requests
from auth0.v3.authentication import GetToken
from auth0.v3.management import Auth0 as Auth0sdk
from fastapi.security.http import HTTPAuthorizationCredentials
from jose import jwt
from starlette.status import HTTP_401_UNAUTHORIZED

from fastapi_cloudauth.auth0 import Auth0, Auth0Claims, Auth0CurrentUser
from fastapi_cloudauth.messages import NOT_VERIFIED
from tests.helpers import (
    Auths,
    BaseTestCloudAuth,
    _assert_verifier,
    _assert_verifier_no_error,
    decode_token,
)

DOMAIN = os.getenv("AUTH0_DOMAIN")
MGMT_CLIENTID = os.getenv("AUTH0_MGMT_CLIENTID")
MGMT_CLIENT_SECRET = os.getenv("AUTH0_MGMT_CLIENT_SECRET")
CLIENTID = os.getenv("AUTH0_CLIENTID")
CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
AUDIENCE = os.getenv("AUTH0_AUDIENCE")
CONNECTION = "Username-Password-Authentication"


def assert_env():
    assert DOMAIN, "'AUTH0_DOMAIN' is not defined. Set environment variables"
    assert (
        MGMT_CLIENTID
    ), "'AUTH0_MGMT_CLIENTID' is not defined. Set environment variables"
    assert (
        MGMT_CLIENT_SECRET
    ), "'AUTH0_MGMT_CLIENT_SECRET' is not defined. Set environment variables"
    assert CLIENTID, "'AUTH0_CLIENTID' is not defined. Set environment variables"
    assert (
        CLIENT_SECRET
    ), "'AUTH0_CLIENT_SECRET' is not defined. Set environment variables"
    assert AUDIENCE, "'AUTH0_AUDIENCE' is not defined. Set environment variables"


def init() -> Auth0sdk:
    """
    instantiate Auth0 SDK class
    Goes to Auth0 dashboard and get followings.
    DOMAIN: domain of Auth0 Dashboard Backend Management Client's Applications
    MGMT_CLIENTID: client ID of Auth0 Dashboard Backend Management Client's Applications
    MGMT_CLIENT_SECRET: client secret of Auth0 Dashboard Backend Management Client's Applications
    """
    get_token = GetToken(DOMAIN)
    token = get_token.client_credentials(
        MGMT_CLIENTID,
        MGMT_CLIENT_SECRET,
        f"https://{DOMAIN}/api/v2/",
    )
    mgmt_api_token = token["access_token"]

    auth0 = Auth0sdk(DOMAIN, mgmt_api_token)
    return auth0


def add_test_user(
    auth0: Auth0sdk,
    username=f"test_user{info.major}{info.minor}@example.com",
    password="testPass1-",
    scopes: Optional[List[str]] = None,
):
    """create test user with Auth0 SDK
    Requirements:
        CLIENTID: client id of `Default App`. See Applications in Auth0 dashboard
        AUDIENCE: create custom API in Auth0 dashboard and add custom permisson (`read:test`).
                    Then, assing that identifier as AUDIENCE.
    """
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
    user_id = f"auth0|{resp.json()['_id']}"

    if scopes:
        auth0.users.add_permissions(
            user_id,
            [
                {"permission_name": scope, "resource_server_identifier": AUDIENCE}
                for scope in scopes
            ],
        )


def delete_user(
    auth0: Auth0sdk,
    username=f"test_user{info.major}{info.minor}@example.com",
    password="testPass1-",
):
    """delete test user with Auth0 SDK"""
    access_token = get_access_token(username=username, password=password)
    if not access_token:
        return
    user_id = jwt.get_unverified_claims(access_token)["sub"]
    auth0.users.delete(user_id)


def get_access_token(
    username=f"test_user{info.major}{info.minor}@example.com",
    password="testPass1-",
) -> Optional[str]:
    """
    Requirements:
        DOMAIN: domain of Auth0 Dashboard Backend Management Client's Applications
        CLIENTID: Set client id of `Default App` in environment variable. See Applications in Auth0 dashboard
        CLIENT_SECRET: Set client secret of `Default App` in environment variable
        AUDIENCE: In Auth0 dashboard, create custom applications and API,
                and add permission `read:test` into that API,
                and then copy the audience (identifier) in environment variable.

    NOTE: the followings setting in Auth0 dashboard is required
        - sidebar > Applications > settings > Advanced settings > grant: click `password` on
        - top right icon > Set General > API Authorization Settings > Default Directory to Username-Password-Authentication
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
    access_token = resp.json().get("access_token")
    return access_token


def get_id_token(
    username=f"test_user{info.major}{info.minor}@example.com",
    password="testPass1-",
) -> Optional[str]:
    """
    Requirements:
        DOMAIN: domain of Auth0 Dashboard Backend Management Client's Applications
        CLIENTID: Set client id of `Default App` in environment variable. See Applications in Auth0 dashboard
        CLIENT_SECRET: Set client secret of `Default App` in environment variable
        AUDIENCE: In Auth0 dashboard, create custom applications and API,
                and add permission `read:test` into that API,
                and then copy the audience (identifier) in environment variable.

    NOTE: the followings setting in Auth0 dashboard is required
        - sidebar > Applications > settings > Advanced settings > grant: click `password` on
        - top right icon > Set General > API Authorization Settings > Default Directory to Username-Password-Authentication
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
        },
    )
    id_token = resp.json().get("id_token")
    return id_token


class Auth0Client(BaseTestCloudAuth):
    """
    NOTE: RBAC setting must be able
    """

    username = f"test_user{info.major}{info.minor}@example.com"
    password = "testPass1-"

    def setup(self, scope: Iterable[str]) -> None:
        assert_env()

        auth0sdk = init()
        self.scope = scope
        self.scope_username = (
            f"{'-'.join(self.scope).replace(':', '-')}{self.username}"
            if self.scope
            else self.username
        )

        delete_user(auth0sdk, username=self.username, password=self.password)
        add_test_user(
            auth0sdk,
            username=self.username,
            password=self.password,
            scopes=[self.scope[0]],
        )
        self.ACCESS_TOKEN = get_access_token(
            username=self.username, password=self.password
        )
        self.ID_TOKEN = get_id_token(username=self.username, password=self.password)

        delete_user(auth0sdk, username=self.scope_username)
        add_test_user(
            auth0sdk,
            username=self.scope_username,
            password=self.password,
            scopes=self.scope,
        )
        self.SCOPE_ACCESS_TOKEN = get_access_token(
            username=self.scope_username, password=self.password
        )

        self.auth0sdk = auth0sdk

        class Auth0InvalidClaims(Auth0Claims):
            fake_field: str

        class Auth0FakeCurrentUser(Auth0CurrentUser):
            user_info = Auth0InvalidClaims

        assert DOMAIN and AUDIENCE and CLIENTID
        self.TESTAUTH = Auths(
            protect_auth=Auth0(domain=DOMAIN, customAPI=AUDIENCE),
            protect_auth_ne=Auth0(domain=DOMAIN, customAPI=AUDIENCE, auto_error=False),
            ms_auth=Auth0CurrentUser(domain=DOMAIN, client_id=CLIENTID),
            ms_auth_ne=Auth0CurrentUser(
                domain=DOMAIN, client_id=CLIENTID, auto_error=False
            ),
            invalid_ms_auth=Auth0FakeCurrentUser(domain=DOMAIN, client_id=CLIENTID),
            invalid_ms_auth_ne=Auth0FakeCurrentUser(
                domain=DOMAIN, client_id=CLIENTID, auto_error=False
            ),
            valid_claim=Auth0Claims,
            invalid_claim=Auth0InvalidClaims,
        )

    def teardown(self):
        delete_user(self.auth0sdk, self.username)
        delete_user(self.auth0sdk, self.scope_username)

    def decode(self):
        # access token
        header, payload, *_ = decode_token(self.ACCESS_TOKEN)
        assert header.get("typ") == "JWT"
        assert [self.scope[0]] == payload.get("permissions")

        # scope access token
        scope_header, scope_payload, *_ = decode_token(self.SCOPE_ACCESS_TOKEN)
        assert scope_header.get("typ") == "JWT"
        assert set(self.scope) == set(scope_payload.get("permissions"))

        # id token
        id_header, id_payload, *_ = decode_token(self.ID_TOKEN)
        assert id_header.get("typ") == "JWT"
        assert id_payload.get("email") == self.username


@pytest.mark.unittest
def test_extra_verify_access_token():
    """
    Testing for access token validation:
    - validate standard claims: Token expiration (exp) and Token issuer (iss)
    - verify token audience (aud) claims
    Ref: https://auth0.com/docs/tokens/access-tokens/validate-access-tokens
    """
    domain = DOMAIN
    customAPI = "https://dummy-domain"
    issuer = "https://dummy"
    auth = Auth0(domain=domain, customAPI=customAPI, issuer=issuer)
    verifier = auth._verifier
    auth_no_error = Auth0(
        domain=domain, customAPI=customAPI, issuer=issuer, auto_error=False
    )
    verifier_no_error = auth_no_error._verifier

    # correct
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": customAPI,
            "iss": issuer,
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    verifier._verify_claims(HTTPAuthorizationCredentials(scheme="a", credentials=token))
    verifier_no_error._verify_claims(
        HTTPAuthorizationCredentials(scheme="a", credentials=token)
    )
    # Testing for validation of JWT standard claims

    # invalid iss
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": customAPI,
            "iss": "invalid" + issuer,
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # invalid expiration
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() - timedelta(hours=5),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": customAPI,
            "iss": issuer,
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # Testing for access token specific verification
    # invalid aud
    # aud must be same as custom API
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": customAPI + "incorrect",
            "iss": issuer,
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)


@pytest.mark.unittest
def test_extra_verify_id_token():
    """
    Testing for ID token validation:
    - validate standard claims: Token expiration (exp) and Token issuer (iss)
    - verify token audience (aud) claims: same as Client ID
    - verify Nonce
    Ref: https://auth0.com/docs/tokens/id-tokens/validate-id-tokens
    """
    domain = DOMAIN
    client_id = "dummy-client-ID"
    nonce = "dummy-nonce"
    issuer = "https://dummy"
    auth = Auth0CurrentUser(
        domain=domain, client_id=client_id, nonce=nonce, issuer=issuer
    )
    verifier = auth._verifier
    auth_no_error = Auth0CurrentUser(
        domain=domain, client_id=client_id, nonce=nonce, issuer=issuer, auto_error=False
    )
    verifier_no_error = auth_no_error._verifier

    # correct
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id,
            "nonce": nonce,
            "iss": issuer,
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    verifier._verify_claims(HTTPAuthorizationCredentials(scheme="a", credentials=token))
    verifier_no_error._verify_claims(
        HTTPAuthorizationCredentials(scheme="a", credentials=token)
    )

    # Testing for validation of JWT standard claims

    # invalid iss
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id,
            "iss": "invalid" + issuer,
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # invalid expiration
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() - timedelta(hours=5),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id,
            "iss": issuer,
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # Testing for ID token specific verification
    # invalid aud
    # aud must be same as Client ID
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id + "incorrect",
            "iss": issuer,
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # invalid nonce
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id,
            "nonce": nonce + "invalid",
            "iss": issuer,
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)
