import os
from sys import version_info as info
import boto3
from typing import Optional
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_cloudauth import Cognito, CognitoCurrentUser
from fastapi_cloudauth.cognito import CognitoClaims

from tests.helpers import BaseTestCloudAuth, decode_token


def add_test_user(
    username=f"test_user{info.major}{info.minor}@example.com",
    password="testPass1-",
    scope: Optional[str] = None,
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


def get_cognito_token(
    username=f"test_user{info.major}{info.minor}@example.com", password="testPass1-"
):
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


def delete_cognito_user(username=f"test_user{info.major}{info.minor}@example.com"):
    try:
        client = boto3.client("cognito-idp", region_name=os.environ["COGNITO_REGION"])
        response = client.admin_delete_user(
            UserPoolId=os.environ["COGNITO_USERPOOLID"], Username=username
        )
    except:
        pass


class CognitoClient(BaseTestCloudAuth):
    scope_user = f"test_scope{info.major}{info.minor}@example.com"
    user = f"test_user{info.major}{info.minor}@example.com"
    password = "testPass1-"
    scope = "read:test"

    def setup(self):
        app = FastAPI()

        region = os.environ["COGNITO_REGION"]
        userPoolId = os.environ["COGNITO_USERPOOLID"]

        auth = Cognito(region=region, userPoolId=userPoolId)
        auth_no_error = Cognito(region=region, userPoolId=userPoolId, auto_error=False)
        get_current_user = CognitoCurrentUser(region=region, userPoolId=userPoolId)
        get_current_user_no_error = CognitoCurrentUser(
            region=region, userPoolId=userPoolId, auto_error=False
        )

        delete_cognito_user(self.user)
        add_test_user(self.user, self.password)
        self.ACCESS_TOKEN, self.ID_TOKEN = get_cognito_token(self.user, self.password)

        delete_cognito_user(self.scope_user)
        add_test_user(self.scope_user, self.password, scope=self.scope)
        self.SCOPE_ACCESS_TOKEN, self.SCOPE_ID_TOKEN = get_cognito_token(
            self.scope_user, self.password
        )

        @app.get("/")
        async def secure(payload=Depends(auth)) -> bool:
            return payload

        @app.get("/no-error/")
        async def secure_no_error(payload=Depends(auth_no_error)):
            assert payload is None

        @app.get("/scope/", dependencies=[Depends(auth.scope(self.scope))])
        async def secure_scope() -> bool:
            pass

        @app.get("/scope/no-error/")
        async def secure_scope_no_error(
            payload=Depends(auth_no_error.scope(self.scope)),
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

        self.TESTCLIENT = TestClient(app)

    def teardown(self):
        delete_cognito_user(self.user)
        delete_cognito_user(self.scope_user)

    def decode(self):
        # access token
        header, payload, *_ = decode_token(self.ACCESS_TOKEN)
        assert not payload.get("cognito:groups")

        # scope token
        scope_header, scope_payload, *_ = decode_token(self.SCOPE_ACCESS_TOKEN)
        assert self.scope in scope_payload.get("cognito:groups")

        # id token
        id_header, id_payload, *_ = decode_token(self.ID_TOKEN)
        assert id_payload.get("email") == self.user

