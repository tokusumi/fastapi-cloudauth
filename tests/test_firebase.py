import os
import base64
import json
from typing import Optional

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from firebase_admin.auth import delete_user
import requests
import firebase_admin
from firebase_admin import auth
from firebase_admin import credentials

from fastapi_cloudauth import FirebaseCurrentUser
from fastapi_cloudauth.firebase import FirebaseClaims

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
    credentials_path = os.path.join(basedir, "credentials", "sa.json")
    with open(credentials_path, "w",) as f:
        json.dump(credentials_json, f)

    cred = credentials.Certificate(credentials_path)
    firebase_admin.initialize_app(cred)


def add_test_user(email, password, uid):
    auth.create_user(email=email, password=password, uid=uid)


def delete_test_user(uid):
    auth.delete_user(uid)


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

    app = FastAPI()

    @app.get("/user/", response_model=FirebaseClaims)
    async def secure_user(current_user: FirebaseClaims = Depends(get_current_user)):
        return current_user

    @app.get("/user/no-error/")
    async def secure_user_no_error(
        current_user: Optional[FirebaseClaims] = Depends(get_current_user_no_error),
    ):
        assert current_user is None

    client = TestClient(app)
    return client


class TestFirebase:
    @classmethod
    def setup_class(cls):
        """set credentials and create test user"""
        cls.email = "fastapi-cloudauth-user@example.com"
        cls.password = "secretPassword"
        cls.uid = "fastapi-cloudauth-test-uid"

        initialize()

        try:
            delete_user(cls.uid)
        except firebase_admin._auth_utils.UserNotFoundError:
            pass

        # create test user
        add_test_user(cls.email, cls.password, cls.uid)

        # get access token and id token
        cls.ACCESS_TOKEN, cls.ID_TOKEN = get_tokens(cls.email, cls.password, cls.uid)

        # set application for testing
        cls.client = get_test_client()

    @classmethod
    def teardown_class(cls):
        """delete test user"""
        delete_user(cls.uid)

    def success_case(self, path: str, token: str = None):
        headers = {}
        if token:
            headers["authorization"] = f"Bearer {token}"
        response = self.client.get(path, headers=headers)
        assert response.status_code == 200, f"{response.json()}"
        return response

    def user_success_case(self, path: str, token: str = None):
        response = self.success_case(path, token)
        for value in response.json().values():
            assert value, f"{response.content} failed to parse"
        return response

    def failure_case(self, path: str, token: str = None):
        headers = {}
        if token:
            headers["authorization"] = f"Bearer {token}"
        response = self.client.get(path, headers=headers)
        assert response.status_code == 403, f"{response.json()}"
        return response

    def test_decode_token(self):
        # access token
        header, payload, *rest = self.ACCESS_TOKEN.split(".")

        header = json.loads(base64.b64decode(header).decode())
        payload = json.loads(base64.b64decode(payload).decode())
        assert header.get("typ") == "JWT"
        assert payload.get("uid") == self.uid

        # id token
        id_header, id_payload, *rest = self.ID_TOKEN.split(".")

        id_header += f"{'=' * (len(id_header) % 4)}"
        id_payload += f"{'=' * (len(id_payload) % 4)}"
        id_header = json.loads(base64.b64decode(id_header).decode())
        id_payload = json.loads(base64.b64decode(id_payload).decode())
        assert id_header.get("typ") == "JWT"
        assert id_payload.get("email") == self.email
        assert id_payload.get("user_id") == self.uid

    def test_valid_id_token(self):
        response = self.success_case("/user/", self.ID_TOKEN)

    def test_no_id_token(self):
        # handle in fastapi.security.HTTPBearer
        self.failure_case("/user/")

    def test_incompatible_kid_id_token(self):
        # manipulate header
        token = self.ID_TOKEN.split(".", 1)[-1]
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIzMDQ5ODE1MWMyMTRiNzg4ZGQ5N2YyMmI4NTQxMGE1In0."
            + token
        )
        self.failure_case("/user/", token)

        # not auto_error
        self.success_case("/user/no-error/", token)

    def test_no_kid_id_token(self):
        # manipulate header
        token = self.ID_TOKEN.split(".", 1)[-1]
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + token
        self.failure_case("/user/", token)

        # not auto_error
        self.success_case("/user/no-error", token)

    def test_not_verified_id_token(self):
        # manipulate public_key
        token = f"{self.ID_TOKEN}"[:-3] + "aaa"
        self.failure_case("/user/", token)

        # not auto_error
        self.success_case("/user/no-error", token)

