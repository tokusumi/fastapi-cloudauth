import os
from sys import version_info as info
import requests
from typing import Optional
from jose import jwt
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from auth0.v3.authentication import GetToken
from auth0.v3.management import Auth0 as Auth0sdk

from fastapi_cloudauth.auth0 import Auth0, Auth0Claims, Auth0CurrentUser

from tests.helpers import BaseTestCloudAuth, decode_token

DOMAIN = os.environ["AUTH0_DOMAIN"]
MGMT_CLIENTID = os.environ["AUTH0_MGMT_CLIENTID"]
MGMT_CLIENT_SECRET = os.environ["AUTH0_MGMT_CLIENT_SECRET"]
CLIENTID = os.environ["AUTH0_CLIENTID"]
CLIENT_SECRET = os.environ["AUTH0_CLIENT_SECRET"]
AUDIENCE = os.environ["AUTH0_AUDIENCE"]
CONNECTION = "Username-Password-Authentication"


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
        MGMT_CLIENTID, MGMT_CLIENT_SECRET, f"https://{DOMAIN}/api/v2/",
    )
    mgmt_api_token = token["access_token"]

    auth0 = Auth0sdk(DOMAIN, mgmt_api_token)
    return auth0


def add_test_user(
    auth0: Auth0sdk,
    username=f"test_user{info.major}{info.minor}@example.com",
    password="testPass1-",
    scope: Optional[str] = None,
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

    if scope:
        auth0.users.add_permissions(
            user_id,
            [{"permission_name": scope, "resource_server_identifier": AUDIENCE,}],
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
    username=f"test_user{info.major}{info.minor}@example.com", password="testPass1-",
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
    username=f"test_user{info.major}{info.minor}@example.com", password="testPass1-",
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
    scope = "read:test"

    def setup(self):
        auth0sdk = init()

        self.scope_username = (
            f"{self.scope.replace(':', '-')}{self.username}"
            if self.scope
            else self.username
        )

        delete_user(auth0sdk, username=self.username, password=self.password)
        add_test_user(auth0sdk, username=self.username, password=self.password)
        self.ACCESS_TOKEN = get_access_token(
            username=self.username, password=self.password
        )
        self.ID_TOKEN = get_id_token(username=self.username, password=self.password)

        delete_user(auth0sdk, username=self.scope_username)
        add_test_user(
            auth0sdk,
            username=self.scope_username,
            password=self.password,
            scope=self.scope,
        )
        self.SCOPE_ACCESS_TOKEN = get_access_token(
            username=self.scope_username, password=self.password
        )

        self.auth0sdk = auth0sdk

        app = FastAPI()

        auth = Auth0(domain=DOMAIN)
        auth_no_error = Auth0(domain=DOMAIN, auto_error=False)
        get_current_user = Auth0CurrentUser(domain=DOMAIN)
        get_current_user_no_error = Auth0CurrentUser(domain=DOMAIN, auto_error=False)

        class Auth0InvalidClaims(Auth0Claims):
            fake_field: str

        class Auth0FakeCurrentUser(Auth0CurrentUser):
            user_info = Auth0InvalidClaims

        get_invalid_userinfo = Auth0FakeCurrentUser(domain=DOMAIN)
        get_invalid_userinfo_no_error = Auth0FakeCurrentUser(
            domain=DOMAIN, auto_error=False
        )

        @app.get("/")
        async def secure(payload=Depends(auth)) -> bool:
            return payload

        @app.get("/no-error/", dependencies=[Depends(auth_no_error)])
        async def secure_no_error(payload=Depends(auth_no_error)) -> bool:
            return payload

        @app.get("/scope/")
        async def secure_scope(payload=Depends(auth.scope(self.scope))) -> bool:
            pass

        @app.get("/scope/no-error/")
        async def secure_scope_no_error(
            payload=Depends(auth_no_error.scope(self.scope)),
        ):
            assert payload is None

        @app.get("/user/", response_model=Auth0Claims)
        async def secure_user(current_user: Auth0Claims = Depends(get_current_user)):
            return current_user

        @app.get("/user/no-error/")
        async def secure_user_no_error(
            current_user: Optional[Auth0Claims] = Depends(get_current_user_no_error),
        ):
            assert current_user is None

        @app.get("/user/invalid/", response_model=Auth0InvalidClaims)
        async def invalid_userinfo(
            current_user: Auth0InvalidClaims = Depends(get_invalid_userinfo),
        ):
            return current_user  # pragma: no cover

        @app.get("/user/invalid/no-error/")
        async def invalid_userinfo_no_error(
            current_user: Optional[Auth0InvalidClaims] = Depends(
                get_invalid_userinfo_no_error
            ),
        ):
            assert current_user is None

        self.TESTCLIENT = TestClient(app)

    def teardown(self):
        delete_user(self.auth0sdk, self.username)
        delete_user(self.auth0sdk, self.scope_username)

    def decode(self):
        # access token
        header, payload, *_ = decode_token(self.ACCESS_TOKEN)
        assert header.get("typ") == "JWT"
        assert not payload.get("permissions")

        # scope access token
        scope_header, scope_payload, *_ = decode_token(self.SCOPE_ACCESS_TOKEN)
        assert scope_header.get("typ") == "JWT"
        assert scope_payload.get("permissions")

        # id token
        id_header, id_payload, *_ = decode_token(self.ID_TOKEN)
        assert id_header.get("typ") == "JWT"
        assert id_payload.get("email") == self.username
