from typing import List

import pytest

from fastapi_cloudauth.base import (
    NOT_AUTHENTICATED,
    NO_PUBLICKEY,
    NOT_VERIFIED,
    SCOPE_NOT_MATCHED,
    NOT_VALIDATED_CLAIMS,
)
from tests.helpers import assert_get_response
from tests.test_auth0 import Auth0Client
from tests.test_cognito import CognitoClient
from tests.test_firebase import FirebaseClient


class BaseTestCloudAuth:
    cloud_auth = None

    @classmethod
    def setup_class(cls):
        """set credentials and create test user"""
        cls.cloud_auth = cls.cloud_auth()
        cls.cloud_auth.setup()

        # get access token and id token
        cls.ACCESS_TOKEN = cls.cloud_auth.ACCESS_TOKEN
        cls.SCOPE_ACCESS_TOKEN = cls.cloud_auth.SCOPE_ACCESS_TOKEN
        cls.ID_TOKEN = cls.cloud_auth.ID_TOKEN

        # set application for testing
        cls.client = cls.cloud_auth.TESTCLIENT

    @classmethod
    def teardown_class(cls):
        """delete test user"""
        cls.cloud_auth.teardown()

    def test_decode_token(self):
        self.cloud_auth.decode()


class AccessTokenTestCase(BaseTestCloudAuth):
    def success_case(self, path: str, token: str = None):
        return assert_get_response(
            client=self.client, endpoint=path, token=token, status_code=200
        )

    def failure_case(self, path: str, token: str = None, detail=""):
        return assert_get_response(
            client=self.client,
            endpoint=path,
            token=token,
            status_code=403,
            detail=detail,
        )

    def test_valid_token(self):
        self.success_case("/", self.ACCESS_TOKEN)

    def test_no_token(self):
        # handle in fastapi.security.HTTPBearer
        self.failure_case("/")
        # not auto_error
        self.success_case("no-error")

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

    def test_invalid_scope(self):
        self.failure_case("/scope/", self.ACCESS_TOKEN, detail=SCOPE_NOT_MATCHED)
        self.success_case("/scope/no-error/", self.ACCESS_TOKEN)


class IdTokenTestCase(BaseTestCloudAuth):
    def success_case(self, path: str, token: str = None):
        return assert_get_response(
            client=self.client, endpoint=path, token=token, status_code=200
        )

    def user_success_case(self, path: str, token: str = None):
        response = self.success_case(path, token)
        for value in response.json().values():
            assert value, f"{response.content} failed to parse"
        return response

    def failure_case(self, path: str, token: str = None, detail=""):
        return assert_get_response(
            client=self.client,
            endpoint=path,
            token=token,
            status_code=403,
            detail=detail,
        )

    def test_valid_id_token(self):
        self.user_success_case("/user/", self.ID_TOKEN)

    def test_no_id_token(self):
        # handle in fastapi.security.HTTPBearer
        self.failure_case("/user/")
        # not auto_error
        self.success_case("/user/no-error")

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
