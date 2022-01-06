import os
from datetime import datetime, timedelta
from sys import version_info as info
from typing import Iterable, List, Optional

import boto3
import pytest
from botocore.exceptions import ClientError
from fastapi.security.http import HTTPAuthorizationCredentials
from jose import jwt
from starlette.status import HTTP_401_UNAUTHORIZED

from fastapi_cloudauth import Cognito, CognitoCurrentUser
from fastapi_cloudauth.cognito import CognitoClaims
from fastapi_cloudauth.messages import NOT_VERIFIED
from tests.helpers import (
    Auths,
    BaseTestCloudAuth,
    _assert_verifier,
    _assert_verifier_no_error,
    decode_token,
)

REGION = os.getenv("COGNITO_REGION")
USERPOOLID = os.getenv("COGNITO_USERPOOLID")
CLIENTID = os.getenv("COGNITO_APP_CLIENT_ID")


def assert_env():
    assert REGION, "'COGNITO_REGION' is not defined. Set environment variables"
    assert USERPOOLID, "'COGNITO_USERPOOLID' is not defined. Set environment variables"
    assert CLIENTID, "'COGNITO_APP_CLIENT_ID' is not defined. Set environment variables"
    assert CLIENTID, "'COGNITO_APP_CLIENT_ID' is not defined. Set environment variables"
    assert os.getenv(
        "AWS_ACCESS_KEY_ID"
    ), "'AWS_ACCESS_KEY_ID' is not defined. Set environment variables"
    assert os.getenv(
        "AWS_SECRET_ACCESS_KEY"
    ), "'AWS_SECRET_ACCESS_KEY' is not defined. Set environment variables"


def initialize():
    client = boto3.client("cognito-idp", region_name=REGION)
    return client


def add_test_user(
    client,
    username=f"test_user{info.major}{info.minor}@example.com",
    password="testPass1-",
    scopes: Optional[List[str]] = None,
):
    client.sign_up(
        ClientId=CLIENTID,
        Username=username,
        Password=password,
        UserAttributes=[{"Name": "email", "Value": username}],
    )
    client.admin_confirm_sign_up(UserPoolId=USERPOOLID, Username=username)
    if scopes:
        for scope in scopes:
            try:
                client.create_group(GroupName=scope, UserPoolId=USERPOOLID)
            except ClientError:  # pragma: no cover
                pass  # pragma: no cover
            client.admin_add_user_to_group(
                UserPoolId=USERPOOLID,
                Username=username,
                GroupName=scope,
            )


def get_cognito_token(
    client,
    username=f"test_user{info.major}{info.minor}@example.com",
    password="testPass1-",
):
    resp = client.admin_initiate_auth(
        UserPoolId=USERPOOLID,
        ClientId=CLIENTID,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = resp["AuthenticationResult"]["AccessToken"]
    id_token = resp["AuthenticationResult"]["IdToken"]
    return access_token, id_token


def delete_cognito_user(
    client,
    username=f"test_user{info.major}{info.minor}@example.com",
):
    try:
        client.admin_delete_user(UserPoolId=USERPOOLID, Username=username)
    except Exception:  # pragma: no cover
        pass  # pragma: no cover


class CognitoClient(BaseTestCloudAuth):
    scope_user = f"test_scope{info.major}{info.minor}@example.com"
    user = f"test_user{info.major}{info.minor}@example.com"
    password = "testPass1-"

    def setup(self, scope: Iterable[str]) -> None:
        assert_env()

        self.scope = scope
        region = REGION
        userPoolId = USERPOOLID

        class CognitoInvalidClaims(CognitoClaims):
            fake_field: str

        class CognitoFakeCurrentUser(CognitoCurrentUser):
            user_info = CognitoInvalidClaims

        self.TESTAUTH = Auths(
            protect_auth=Cognito(
                region=region, userPoolId=userPoolId, client_id=CLIENTID
            ),
            protect_auth_ne=Cognito(
                region=region,
                userPoolId=userPoolId,
                client_id=CLIENTID,
                auto_error=False,
            ),
            ms_auth=CognitoCurrentUser(
                region=region, userPoolId=userPoolId, client_id=CLIENTID
            ),
            ms_auth_ne=CognitoCurrentUser(
                region=region,
                userPoolId=userPoolId,
                client_id=CLIENTID,
                auto_error=False,
            ),
            invalid_ms_auth=CognitoFakeCurrentUser(
                region=region, userPoolId=userPoolId, client_id=CLIENTID
            ),
            invalid_ms_auth_ne=CognitoFakeCurrentUser(
                region=region,
                userPoolId=userPoolId,
                client_id=CLIENTID,
                auto_error=False,
            ),
            valid_claim=CognitoClaims,
            invalid_claim=CognitoInvalidClaims,
        )

        self.client = initialize()

        delete_cognito_user(self.client, self.user)
        add_test_user(self.client, self.user, self.password, scopes=[self.scope[0]])
        self.ACCESS_TOKEN, self.ID_TOKEN = get_cognito_token(
            self.client, self.user, self.password
        )

        delete_cognito_user(self.client, self.scope_user)
        add_test_user(self.client, self.scope_user, self.password, scopes=self.scope)
        self.SCOPE_ACCESS_TOKEN, self.SCOPE_ID_TOKEN = get_cognito_token(
            self.client, self.scope_user, self.password
        )

    def teardown(self):
        delete_cognito_user(self.client, self.user)
        delete_cognito_user(self.client, self.scope_user)

    def decode(self):
        # access token
        header, payload, *_ = decode_token(self.ACCESS_TOKEN)
        assert [self.scope[0]] == payload.get("cognito:groups")

        # scope token
        scope_header, scope_payload, *_ = decode_token(self.SCOPE_ACCESS_TOKEN)
        assert set(self.scope) == set(scope_payload.get("cognito:groups"))

        # id token
        id_header, id_payload, *_ = decode_token(self.ID_TOKEN)
        assert id_payload.get("email") == self.user


@pytest.mark.unittest
def test_extra_verify_access_token():
    """
    Testing for access token validation:
    - validate standard claims:
        - exp: Token expiration
        - aud: audience should match the app client ID
        - iss: Token issuer should match your user pool
        - token_use: should match `id`
    Ref: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html#amazon-cognito-user-pools-using-tokens-step-3
    """
    region = REGION
    userPoolId = USERPOOLID
    client_id = "dummyclientid"
    auth = Cognito(region=region, userPoolId=userPoolId, client_id=client_id)
    verifier = auth._verifier
    auth_no_error = Cognito(
        region=region, userPoolId=userPoolId, client_id=client_id, auto_error=False
    )
    verifier_no_error = auth_no_error._verifier

    # correct
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id,
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
            "token_use": "access",
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    verifier._verify_claims(HTTPAuthorizationCredentials(scheme="a", credentials=token))
    verifier_no_error._verify_claims(
        HTTPAuthorizationCredentials(scheme="a", credentials=token)
    )

    # invalid exp
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() - timedelta(hours=5),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id,
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
            "token_use": "access",
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # invalid aud
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id + "incorrect",
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
            "token_use": "access",
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # invalid iss
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id,
            "iss": "invalid"
            + f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}-invalid",
            "token_use": "access",
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # invalid token-use
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id,
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}-invalid",
            "token_use": "id",
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
    - validate standard claims:
        - exp: Token expiration
        - aud: audience should match the app client ID
        - iss: Token issuer should match your user pool
        - token_use: should match `id`
    Ref: https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html#amazon-cognito-user-pools-using-tokens-step-3
    """
    region = REGION
    userPoolId = USERPOOLID
    client_id = "dummyclientid"
    auth = CognitoCurrentUser(region=region, userPoolId=userPoolId, client_id=client_id)
    verifier = auth._verifier
    auth_no_error = CognitoCurrentUser(
        region=region, userPoolId=userPoolId, client_id=client_id, auto_error=False
    )
    verifier_no_error = auth_no_error._verifier

    # correct
    token = jwt.encode(
        {
            "at_hash": "some-hash-that-isnt-checked",
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id,
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
            "token_use": "id",
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    verifier._verify_claims(HTTPAuthorizationCredentials(scheme="a", credentials=token))
    verifier_no_error._verify_claims(
        HTTPAuthorizationCredentials(scheme="a", credentials=token)
    )
    # invalid exp
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() - timedelta(hours=5),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id,
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
            "token_use": "id",
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # invalid aud
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id + "incorrect",
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
            "token_use": "id",
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # invalid iss
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id,
            "iss": "invalid"
            + f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}-invalid",
            "token_use": "id",
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # invalid token-use
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() - timedelta(hours=10),
            "aud": client_id,
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
            "token_use": "access",
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)
