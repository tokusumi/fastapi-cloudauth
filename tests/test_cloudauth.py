from typing import Iterable, Optional, Type

import pytest
from fastapi import Depends
from fastapi.applications import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel
from requests.models import Response

from fastapi_cloudauth.messages import (
    NO_PUBLICKEY,
    NOT_AUTHENTICATED,
    NOT_VALIDATED_CLAIMS,
    NOT_VERIFIED,
    SCOPE_NOT_MATCHED,
)
from fastapi_cloudauth.verification import Operator
from tests.helpers import BaseTestCloudAuth as Base
from tests.helpers import assert_get_response
from tests.test_auth0 import Auth0Client
from tests.test_cognito import CognitoClient
from tests.test_firebase import FirebaseClient


class BaseTestCase:
    scope = ("read:test", "write:test")
    verify_access_token = False
    verify_id_token = False
    ACCESS_TOKEN = ""
    SCOPE_ACCESS_TOKEN = ""
    ID_TOKEN = ""
    client: TestClient
    cloud_auth: Type[Base]
    _cloud_auth: Base

    @classmethod
    def setup_class(cls):
        """set credentials and create test user"""
        cls._cloud_auth = cls.cloud_auth()
        cls._cloud_auth.setup(cls.scope)

        # get access token and id token
        cls.ACCESS_TOKEN = cls._cloud_auth.ACCESS_TOKEN
        cls.SCOPE_ACCESS_TOKEN = cls._cloud_auth.SCOPE_ACCESS_TOKEN
        cls.ID_TOKEN = cls._cloud_auth.ID_TOKEN

        # set application for testing
        app = FastAPI()
        if cls.verify_access_token:
            app = add_endpoint_for_accesstoken(app, cls._cloud_auth, cls.scope)
        if cls.verify_id_token:
            app = add_endpoint_for_idtoken(app, cls._cloud_auth)
        cls.client = TestClient(app)

    @classmethod
    def teardown_class(cls):
        """delete test user"""
        cls._cloud_auth.teardown()

    def test_decode_token(self):
        self._cloud_auth.decode()


def add_endpoint_for_accesstoken(
    app: FastAPI, auth: Base, scope: Iterable[str]
) -> FastAPI:
    t = auth.TESTAUTH

    @app.get("/")
    async def secure(payload: bool = Depends(t.protect_auth)) -> bool:
        return payload

    @app.get("/no-error/", dependencies=[Depends(t.protect_auth_ne)])
    async def secure_no_error(payload=Depends(t.protect_auth_ne)) -> bool:
        return payload

    class AccessClaim(BaseModel):
        sub: str = None

    @app.get("/access/user")
    async def secure_access_user(
        payload: AccessClaim = Depends(t.protect_auth.claim(AccessClaim)),
    ):
        assert isinstance(payload, AccessClaim)
        return payload

    @app.get("/access/user/no-error/")
    async def secure_access_user_no_error(
        payload: AccessClaim = Depends(t.protect_auth_ne.claim(AccessClaim)),
    ) -> Optional[AccessClaim]:
        return payload

    class InvalidAccessClaim(BaseModel):
        fake_field: str

    @app.get("/access/user/invalid")
    async def invalid_access_user(
        payload=Depends(t.protect_auth.claim(InvalidAccessClaim)),
    ):
        return payload  # pragma: no cover

    @app.get("/access/user/invalid/no-error/")
    async def invalid_access_user_no_error(
        payload=Depends(t.protect_auth_ne.claim(InvalidAccessClaim)),
    ) -> Optional[InvalidAccessClaim]:
        assert payload is None

    @app.get("/scope/")
    async def secure_scope(payload=Depends(t.protect_auth.scope(scope))) -> bool:
        pass

    @app.get("/scope/no-error/")
    async def secure_scope_no_error(payload=Depends(t.protect_auth_ne.scope(scope))):
        assert payload is None

    @app.get("/scope-any/")
    async def secure_scope_any(
        payload=Depends(t.protect_auth.scope(scope, op=Operator._any))
    ) -> bool:
        pass

    return app


class AccessTokenTestCase(BaseTestCase):
    verify_access_token = True

    @classmethod
    def success_case(self, path: str, token: str = "") -> Response:
        return assert_get_response(
            client=self.client, endpoint=path, token=token, status_code=200
        )

    def userinfo_success_case(self, path: str, token: str = "") -> Response:
        response = self.success_case(path, token)
        for value in response.json().values():
            assert value, f"{response.content} failed to parse"
        return response

    def failure_case(
        self, path: str, token: str = "", detail: str = "", status=401
    ) -> Response:
        return assert_get_response(
            client=self.client,
            endpoint=path,
            token=token,
            status_code=status,
            detail=detail,
        )

    def test_valid_token(self):
        self.success_case("/", self.ACCESS_TOKEN)

    def test_no_token(self):
        self.failure_case("/")
        # not auto_error
        self.success_case("no-error")

    def test_malformed_token(self):
        # given malformed token
        self.failure_case("/", "invaid-format-token", detail=NOT_AUTHENTICATED)
        # not auto_error
        self.success_case("no-error", "invaid-format-token")

    def test_incompatible_kid_token(self):
        # manipulate header
        token = self.ACCESS_TOKEN.split(".", 1)[-1]
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIzMDQ5ODE1MWMyMTRiNzg4ZGQ5N2YyMmI4NTQxMGE1In0."
            + token
        )
        self.failure_case("/", token, detail=NO_PUBLICKEY)
        # not auto_error
        self.success_case("no-error", token)

    def test_no_kid_token(self):
        # manipulate header
        token = self.ACCESS_TOKEN.split(".", 1)[-1]
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + token
        self.failure_case("/", token, detail=NOT_AUTHENTICATED)
        # not auto_error
        self.success_case("no-error", token)

    def test_not_verified_token(self):
        # manipulate public_key
        token = self.ACCESS_TOKEN[:-3] + "aaa"
        self.failure_case("/", token, detail=NOT_VERIFIED)
        # not auto_error
        self.success_case("no-error", token)

    def test_valid_scope(self):
        self.success_case("/scope/", self.SCOPE_ACCESS_TOKEN)

    def test_valid_scope_any(self):
        # access token must include a part of scopes in SCOPE_ACCESS_TOKEN
        self.success_case("/scope-any/", self.ACCESS_TOKEN)

    def test_invalid_scope(self):
        self.failure_case(
            "/scope/", self.ACCESS_TOKEN, detail=SCOPE_NOT_MATCHED, status=403
        )
        self.success_case("/scope/no-error/", self.ACCESS_TOKEN)

    def test_malformed_token_for_scope(self):
        # given malformed token
        self.failure_case("/scope/", "invaid-format-token", detail=NOT_AUTHENTICATED)
        # not auto_error
        self.success_case("/scope/no-error", "invaid-format-token")

    def test_valid_token_extraction(self):
        self.userinfo_success_case("/access/user", self.ACCESS_TOKEN)

    def test_no_token_extraction(self):
        self.failure_case("/access/user")
        # not auto_error
        self.success_case("/access/user/no-error")

    def test_insufficient_user_info_from_access_token(self):
        # verified but token does not contains user info
        self.failure_case(
            "/access/user/invalid/", self.ACCESS_TOKEN, detail=NOT_VALIDATED_CLAIMS
        )
        # not auto_error
        self.success_case("/access/user/invalid/no-error", self.ACCESS_TOKEN)


def add_endpoint_for_idtoken(app: FastAPI, auth: Base) -> FastAPI:
    t = auth.TESTAUTH

    @app.get("/user/", response_model=t.valid_claim)
    async def secure_user(current_user: t.valid_claim = Depends(t.ms_auth)):
        return current_user

    @app.get("/user/no-error/")
    async def secure_user_no_error(
        current_user: Optional[t.valid_claim] = Depends(t.ms_auth_ne),
    ):
        assert current_user is None

    @app.get("/user/invalid/", response_model=t.invalid_claim)
    async def invalid_userinfo(
        current_user: t.invalid_claim = Depends(t.invalid_ms_auth),
    ):
        return current_user  # pragma: no cover

    @app.get("/user/invalid/no-error/")
    async def invalid_userinfo_no_error(
        current_user: Optional[t.invalid_claim] = Depends(t.invalid_ms_auth_ne),
    ):
        assert current_user is None

    return app


class IdTokenTestCase(BaseTestCase):
    verify_id_token = True

    def success_case(self, path: str, token: str = "") -> Response:
        return assert_get_response(
            client=self.client, endpoint=path, token=token, status_code=200
        )

    def user_success_case(self, path: str, token: str = "") -> Response:
        response = self.success_case(path, token)
        for value in response.json().values():
            assert value, f"{response.content} failed to parse"
        return response

    def failure_case(
        self, path: str, token: str = "", detail: str = "", status=401
    ) -> Response:
        return assert_get_response(
            client=self.client,
            endpoint=path,
            token=token,
            status_code=status,
            detail=detail,
        )

    def test_valid_id_token(self):
        self.user_success_case("/user/", self.ID_TOKEN)

    def test_no_id_token(self):
        # handle in fastapi.security.HTTPBearer
        self.failure_case("/user/")
        # not auto_error
        self.success_case("/user/no-error")

    def test_malformed_token_for_scope(self):
        # given malformed token
        self.failure_case("/user/", "invaid-format-token", detail=NOT_AUTHENTICATED)
        # not auto_error
        self.success_case("/user/no-error", "invaid-format-token")

    def test_incompatible_kid_id_token(self):
        # manipulate header
        token = self.ID_TOKEN.split(".", 1)[-1]
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIzMDQ5ODE1MWMyMTRiNzg4ZGQ5N2YyMmI4NTQxMGE1In0."
            + token
        )
        self.failure_case("/user/", token, detail=NO_PUBLICKEY)
        # not auto_error
        self.success_case("/user/no-error/", token)

    def test_no_kid_id_token(self):
        # manipulate header
        token = self.ID_TOKEN.split(".", 1)[-1]
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + token
        self.failure_case("/user/", token, detail=NOT_AUTHENTICATED)
        # not auto_error
        self.success_case("/user/no-error", token)

    def test_not_verified_id_token(self):
        # manipulate public_key
        token = f"{self.ID_TOKEN}"[:-3] + "aaa"
        self.failure_case("/user/", token, detail=NOT_VERIFIED)
        # not auto_error
        self.success_case("/user/no-error", token)

    def test_insufficient_current_user_info(self):
        # verified but token does not contains user info
        self.failure_case("/user/invalid/", self.ID_TOKEN, detail=NOT_VALIDATED_CLAIMS)
        # not auto_error
        self.success_case("/user/invalid/no-error", self.ID_TOKEN)


@pytest.mark.auth0
class TestAuth0(AccessTokenTestCase, IdTokenTestCase):
    cloud_auth = Auth0Client


@pytest.mark.cognito
class TestCognito(AccessTokenTestCase, IdTokenTestCase):
    cloud_auth = CognitoClient


@pytest.mark.firebase
class TestFirebase(IdTokenTestCase):
    cloud_auth = FirebaseClient
