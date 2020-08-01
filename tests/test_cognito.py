import os
import boto3
from typing import Optional
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_auth import Cognito as Auth, CognitoCurrentUser
from fastapi_auth.cognito import CognitoClaims


def add_test_user(
    username="test_user@example.com", password="testPass1-", scope: Optional[str] = None
):
    client = boto3.client("cognito-idp", region_name=os.environ["COGNITO_REGION"])
    resp = client.sign_up(
        ClientId=os.environ["COGNITO_APP_CLIENT_ID"],
        Username=username,
        Password=password,
        UserAttributes=[{"Name": "email", "Value": username},],
    )
    resp = client.admin_confirm_sign_up(
        UserPoolId=os.environ["COGNITO_USERPOOLID"], Username=username
    )
    if scope:
        resp = client.admin_add_user_to_group(
            UserPoolId=os.environ["COGNITO_USERPOOLID"],
            Username=username,
            GroupName=scope,
        )


def get_cognito_token(username="test_user@example.com", password="testPass1-"):
    client = boto3.client("cognito-idp", region_name=os.environ["COGNITO_REGION"])
    resp = client.admin_initiate_auth(
        UserPoolId=os.environ["COGNITO_USERPOOLID"],
        ClientId=os.environ["COGNITO_APP_CLIENT_ID"],
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = resp["AuthenticationResult"]["AccessToken"]
    id_token = resp["AuthenticationResult"]["IdToken"]
    return access_token, id_token


def delete_cognito_user(username="test_user@example.com"):
    try:
        client = boto3.client("cognito-idp", region_name=os.environ["COGNITO_REGION"])
        response = client.admin_delete_user(
            UserPoolId=os.environ["COGNITO_USERPOOLID"], Username=username
        )
    except:
        pass


class TestCognito:
    scope_user = "test_scope@example.com"
    scope = "read:test"

    @classmethod
    def setup_class(cls):
        app = FastAPI()

        region = os.environ["COGNITO_REGION"]
        userPoolId = os.environ["COGNITO_USERPOOLID"]

        auth = Auth(region=region, userPoolId=userPoolId)
        auth_no_error = Auth(region=region, userPoolId=userPoolId, auto_error=False)
        get_current_user = CognitoCurrentUser(region=region, userPoolId=userPoolId)
        get_current_user_no_error = CognitoCurrentUser(
            region=region, userPoolId=userPoolId, auto_error=False
        )

        delete_cognito_user()
        add_test_user()
        cls.ACCESS_TOKEN, cls.ID_TOKEN = get_cognito_token()

        delete_cognito_user(cls.scope_user)
        add_test_user(cls.scope_user, scope=cls.scope)
        cls.SCOPE_ACCESS_TOKEN, cls.SCOPE_ID_TOKEN = get_cognito_token(cls.scope_user)

        @app.get("/")
        async def secure(payload=Depends(auth)) -> bool:
            return payload

        @app.get("/no-error/")
        async def secure_no_error(payload=Depends(auth_no_error)):
            assert payload is None

        @app.get("/scope/", dependencies=[Depends(auth.scope(cls.scope))])
        async def secure_scope() -> bool:
            pass

        @app.get("/scope/no-error/")
        async def secure_scope_no_error(
            payload=Depends(auth_no_error.scope(cls.scope)),
        ):
            assert payload is None

        @app.get("/user/", response_model=CognitoClaims)
        async def secure_user(current_user: CognitoClaims = Depends(get_current_user)):
            return current_user

        @app.get("/user/no-error/")
        async def secure_user_no_error(
            current_user: Optional[CognitoClaims] = Depends(get_current_user_no_error),
        ):
            assert current_user is None

        cls.client = TestClient(app)

    @classmethod
    def teardown_class(cls):
        delete_cognito_user()
        delete_cognito_user(cls.scope_user)

    def test_valid_token(self):
        response = self.client.get(
            "/", headers={"authorization": f"Bearer {self.ACCESS_TOKEN}"}
        )
        assert response.status_code == 200, f"{response.json()}"
        assert response.content == b"true"

    def test_no_token(self):
        # handle in fastapi.security.HtTPBearer
        response = self.client.get("/")
        assert response.status_code == 403, f"{response.json()}"

    def test_incompatible_kid_token(self):
        # manipulate header
        token = self.ACCESS_TOKEN.split(".", 1)[-1]
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIzMDQ5ODE1MWMyMTRiNzg4ZGQ5N2YyMmI4NTQxMGE1In0."
            + token
        )
        response = self.client.get("/", headers={"authorization": f"Bearer {token}"})
        assert response.status_code == 403, f"{response.json()}"

        # not auto_error
        response = self.client.get(
            "/no-error/", headers={"authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200, f"{response.json()}"

    def test_no_kid_token(self):
        # manipulate header
        token = self.ACCESS_TOKEN.split(".", 1)[-1]
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + token
        response = self.client.get("/", headers={"authorization": f"Bearer {token}"})
        assert response.status_code == 403, f"{response.json()}"

        # not auto_error
        response = self.client.get(
            "/no-error/", headers={"authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200, f"{response.json()}"

    def test_not_verified_token(self):
        # manipulate public_key
        response = self.client.get(
            "/", headers={"authorization": f"Bearer {self.ACCESS_TOKEN}"[:-3] + "aaa"}
        )
        assert response.status_code == 403, f"{response.json()}"

        # not auto_error
        response = self.client.get(
            "/no-error/",
            headers={"authorization": f"Bearer {self.ACCESS_TOKEN}"[:-3] + "aaa"},
        )
        assert response.status_code == 200, f"{response.json()}"

    def test_valid_scope(self):
        response = self.client.get(
            "/scope/", headers={"authorization": f"Bearer {self.SCOPE_ACCESS_TOKEN}"}
        )
        assert response.status_code == 200, f"{response.json()}"

    def test_invalid_scope(self):
        response = self.client.get(
            "/scope/", headers={"authorization": f"Bearer {self.ACCESS_TOKEN}"}
        )
        assert response.status_code == 403, f"{response.json()}"

        response = self.client.get(
            "/scope/no-error/", headers={"authorization": f"Bearer {self.ACCESS_TOKEN}"}
        )
        assert response.status_code == 200, f"{response.json()}"

    def test_get_current_user(self):
        response = self.client.get(
            "/user/", headers={"authorization": f"Bearer {self.ID_TOKEN}"}
        )
        assert response.status_code == 200, f"{response.json()}"
        for value in response.json().values():
            assert value, f"{response.content} failed to parse"

    def test_not_verified_user_no_error(self):
        response = self.client.get(
            "/user/no-error/",
            headers={"authorization": f"Bearer {self.ID_TOKEN}"[:-3] + "aaa"},
        )
        assert response.status_code == 200, f"{response.json()}"

    def test_insufficient_current_user_info(self):
        response = self.client.get(
            "/user/", headers={"authorization": f"Bearer {self.ACCESS_TOKEN}"}
        )
        assert response.status_code == 403, f"{response.json()}"

    def test_insufficient_current_user_info_no_error(self):
        response = self.client.get(
            "/user/no-error/", headers={"authorization": f"Bearer {self.ACCESS_TOKEN}"}
        )
        assert response.status_code == 200, f"{response.json()}"
