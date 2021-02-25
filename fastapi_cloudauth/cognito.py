from typing import Any, Optional

from pydantic import BaseModel, Field

from .base import ScopedAuth, UserInfoAuth
from .verification import JWKS


class Cognito(ScopedAuth):
    """
    Verify access token of AWS Cognito
    """

    user_info = None

    def __init__(
        self,
        region: str,
        userPoolId: str,
        scope_key: Optional[str] = "cognito:groups",
        auto_error: bool = True,
    ):
        url = f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json"
        jwks = JWKS.fromurl(url)
        super().__init__(
            jwks, scope_key=scope_key, auto_error=auto_error,
        )


class CognitoClaims(BaseModel):
    username: str = Field(alias="cognito:username")
    email: str = Field(None, alias="email")


class CognitoCurrentUser(UserInfoAuth):
    """
    Verify ID token and get user info of AWS Cognito
    """

    user_info = CognitoClaims

    def __init__(
        self, region: str, userPoolId: str, *args: Any, **kwargs: Any,
    ):
        url = f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json"
        jwks = JWKS.fromurl(url)
        super().__init__(jwks, user_info=self.user_info, *args, **kwargs)
