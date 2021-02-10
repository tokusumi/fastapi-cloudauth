import os
import base64
import json
from typing import Optional
from sys import version_info as info

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from firebase_admin.auth import delete_user
import requests
import firebase_admin
from firebase_admin import auth
from firebase_admin import credentials

from fastapi_cloudauth import FirebaseCurrentUser
from fastapi_cloudauth.firebase import FirebaseClaims

from tests.helpers import assert_get_response, decode_token, BaseTestCloudAuth

API_KEY = os.getenv("FIREBASE_APIKEY")
_verify_password_url = (
    "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword"
)


def initialize():
    """set credentials (intermediate credential file is created)"""
    credentials_base64 = os.getenv("FIREBASE_BASE64_CREDENCIALS")
    credentials_str = base64.b64decode(credentials_base64)
    credentials_json = json.loads(credentials_str)
    basedir = os.path.dirname(os.path.dirname(__file__))
    credentials_dirpath = os.path.join(basedir, "credentials")
    os.makedirs(credentials_dirpath, exist_ok=True)
    credentials_path = os.path.join(credentials_dirpath, "sa.json")
    with open(credentials_path, "w",) as f:
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

    get_current_user = FirebaseCurrentUser()
    get_current_user_no_error = FirebaseCurrentUser(auto_error=False)

    class FirebaseInvalidClaims(FirebaseClaims):
        fake_field: str

    class FirebaseFakeCurrentUser(FirebaseCurrentUser):
        user_info = FirebaseInvalidClaims

    get_invalid_userinfo = FirebaseFakeCurrentUser()
    get_invalid_userinfo_no_error = FirebaseFakeCurrentUser(auto_error=False)

    app = FastAPI()

    @app.get("/user/", response_model=FirebaseClaims)
    async def secure_user(current_user: FirebaseClaims = Depends(get_current_user)):
        return current_user

    @app.get("/user/no-error/")
    async def secure_user_no_error(
        current_user: Optional[FirebaseClaims] = Depends(get_current_user_no_error),
    ):
        assert current_user is None

        @app.get("/user/invalid/", response_model=FirebaseInvalidClaims)
        async def invalid_userinfo(
            current_user: FirebaseInvalidClaims = Depends(get_invalid_userinfo),
        ):
            return current_user  # pragma: no cover

        @app.get("/user/invalid/no-error/")
        async def invalid_userinfo_no_error(
            current_user: Optional[FirebaseInvalidClaims] = Depends(
                get_invalid_userinfo_no_error
            ),
        ):
            assert current_user is None

    client = TestClient(app)
    return client


class FirebaseClient(BaseTestCloudAuth):
    def setup(self):
        """set credentials and create test user"""
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
        self.TESTCLIENT = get_test_client()

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
