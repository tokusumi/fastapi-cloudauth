import base64
import json
import os
import tempfile
from calendar import timegm
from datetime import datetime, timedelta
from sys import version_info as info
from typing import Iterable

import firebase_admin
import pytest
import requests
from fastapi.security.http import HTTPAuthorizationCredentials
from firebase_admin import auth, credentials
from jose import jwt
from starlette.status import HTTP_401_UNAUTHORIZED

from fastapi_cloudauth import FirebaseCurrentUser
from fastapi_cloudauth.firebase import FirebaseClaims
from fastapi_cloudauth.messages import NOT_VERIFIED
from tests.helpers import (
    Auths,
    BaseTestCloudAuth,
    _assert_verifier,
    _assert_verifier_no_error,
    decode_token,
)

PROJECT_ID = os.getenv("FIREBASE_PROJECTID")
API_KEY = os.getenv("FIREBASE_APIKEY")
BASE64_CREDENTIAL = os.getenv("FIREBASE_BASE64_CREDENCIALS")
_verify_password_url = (
    "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword"
)


def assert_env():
    assert API_KEY, "'FIREBASE_APIKEY' is not defined. Set environment variables"
    assert (
        BASE64_CREDENTIAL
    ), "'FIREBASE_BASE64_CREDENCIALS' is not defined. Set environment variables"


def initialize():
    """set credentials (intermediate credential file is created)"""
    credentials_base64 = BASE64_CREDENTIAL
    credentials_str = base64.b64decode(credentials_base64)
    credentials_json = json.loads(credentials_str)

    tmpdir = tempfile.TemporaryDirectory()
    credentials_path = os.path.join(tmpdir.name, "sa.json")
    with open(
        credentials_path,
        "w",
    ) as f:
        json.dump(credentials_json, f)

    cred = credentials.Certificate(credentials_path)
    firebase_admin.initialize_app(cred)


def add_test_user(email, password, uid):
    auth.create_user(email=email, password=password, uid=uid)


def delete_test_user(uid):
    try:
        auth.delete_user(uid)
    except firebase_admin._auth_utils.UserNotFoundError:
        pass


def get_tokens(email, password, uid):
    # get access token
    access_token_bytes = auth.create_custom_token(uid)
    ACCESS_TOKEN = access_token_bytes.decode("utf-8")

    # get ID token (sign-in with password using FIREBASE AUTH REST API)
    body = {"email": email, "password": password, "returnSecureToken": True}
    params = {"key": API_KEY}
    resp = requests.request("post", _verify_password_url, params=params, json=body)
    resp.raise_for_status()
    ID_TOKEN = resp.json().get("idToken")

    return ACCESS_TOKEN, ID_TOKEN


def get_test_client():
    class FirebaseInvalidClaims(FirebaseClaims):
        fake_field: str

    class FirebaseFakeCurrentUser(FirebaseCurrentUser):
        user_info = FirebaseInvalidClaims

    return Auths(
        protect_auth=None,
        protect_auth_ne=None,
        ms_auth=FirebaseCurrentUser(project_id=PROJECT_ID),
        ms_auth_ne=FirebaseCurrentUser(project_id=PROJECT_ID, auto_error=False),
        invalid_ms_auth=FirebaseFakeCurrentUser(project_id=PROJECT_ID),
        invalid_ms_auth_ne=FirebaseFakeCurrentUser(
            project_id=PROJECT_ID, auto_error=False
        ),
        valid_claim=FirebaseClaims,
        invalid_claim=FirebaseInvalidClaims,
    )


class FirebaseClient(BaseTestCloudAuth):
    def setup(self, scope: Iterable[str]) -> None:
        """set credentials and create test user"""
        assert_env()

        self.email = f"fastapi-cloudauth-user-py{info.major}{info.minor}@example.com"
        self.password = "secretPassword"
        self.uid = f"fastapi-cloudauth-test-uid-py{info.major}{info.minor}"

        initialize()

        delete_test_user(self.uid)

        # create test user
        add_test_user(self.email, self.password, self.uid)

        # get access token and id token
        self.ACCESS_TOKEN, self.ID_TOKEN = get_tokens(
            self.email, self.password, self.uid
        )

        # set application for testing
        self.TESTAUTH = get_test_client()

    def teardown(self):
        """delete test user"""
        delete_test_user(self.uid)

    def decode(self):
        # access token
        header, payload, *_ = decode_token(self.ACCESS_TOKEN)
        assert header.get("typ") == "JWT"
        assert payload.get("uid") == self.uid

        # id token
        id_header, id_payload, *_ = decode_token(self.ID_TOKEN)
        assert id_header.get("typ") == "JWT"
        assert id_payload.get("email") == self.email
        assert id_payload.get("user_id") == self.uid


@pytest.mark.unittest
def test_extra_verify_token():
    """
    Testing for ID token validation:
    - validate standard claims:
        - exp: Token expiration
        - iat:
        - aud: audience is same as project ID
        - iss: Token issuer
        - sub: not null string or user id
        - auth_time: authorization time is the past
    Ref: https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
    """
    pjt_id = "dummy"
    auth = FirebaseCurrentUser(pjt_id)
    verifier = auth._verifier
    auth_no_error = FirebaseCurrentUser(pjt_id, auto_error=False)
    verifier_no_error = auth_no_error._verifier

    # correct
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": timegm((datetime.utcnow() + timedelta(hours=10)).utctimetuple()),
            "iat": timegm((datetime.utcnow() - timedelta(hours=10)).utctimetuple()),
            "auth_time": timegm(
                (datetime.utcnow() - timedelta(hours=10)).utctimetuple()
            ),
            "aud": pjt_id,
            "iss": f"https://securetoken.google.com/{pjt_id}",
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
            "exp": timegm((datetime.utcnow() - timedelta(hours=10)).utctimetuple()),
            "iat": timegm((datetime.utcnow() - timedelta(hours=10)).utctimetuple()),
            "auth_time": timegm(
                (datetime.utcnow() - timedelta(hours=11)).utctimetuple()
            ),
            "aud": pjt_id,
            "iss": f"https://securetoken.google.com/{pjt_id}",
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # invalid iat
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": timegm((datetime.utcnow() + timedelta(hours=10)).utctimetuple()),
            "iat": timegm((datetime.utcnow() + timedelta(hours=10)).utctimetuple()),
            "auth_time": timegm(
                (datetime.utcnow() - timedelta(hours=11)).utctimetuple()
            ),
            "aud": pjt_id,
            "iss": f"https://securetoken.google.com/{pjt_id}",
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
            "exp": timegm((datetime.utcnow() + timedelta(hours=10)).utctimetuple()),
            "iat": timegm((datetime.utcnow() - timedelta(hours=10)).utctimetuple()),
            "auth_time": timegm(
                (datetime.utcnow() - timedelta(hours=11)).utctimetuple()
            ),
            "aud": pjt_id + "incorrect",
            "iss": f"https://securetoken.google.com/{pjt_id}",
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
            "exp": timegm((datetime.utcnow() + timedelta(hours=10)).utctimetuple()),
            "iat": timegm((datetime.utcnow() - timedelta(hours=10)).utctimetuple()),
            "auth_time": timegm(
                (datetime.utcnow() - timedelta(hours=11)).utctimetuple()
            ),
            "aud": pjt_id,
            "iss": f"https://securetoken.google.com/{pjt_id}-extra",
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # invalid sub
    token = jwt.encode(
        {
            "sub": "",
            "exp": timegm((datetime.utcnow() + timedelta(hours=10)).utctimetuple()),
            "iat": timegm((datetime.utcnow() - timedelta(hours=10)).utctimetuple()),
            "auth_time": timegm(
                (datetime.utcnow() - timedelta(hours=11)).utctimetuple()
            ),
            "aud": pjt_id,
            "iss": f"https://securetoken.google.com/{pjt_id}-extra",
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # invalid auth_time
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": timegm((datetime.utcnow() + timedelta(hours=10)).utctimetuple()),
            "iat": timegm((datetime.utcnow() - timedelta(hours=10)).utctimetuple()),
            "auth_time": timegm(
                (datetime.utcnow() + timedelta(hours=3)).utctimetuple()
            ),
            "aud": pjt_id,
            "iss": f"https://securetoken.google.com/{pjt_id}",
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)
