from pydantic import BaseModel, Field
from .base import TokenVerifier, TokenUserInfoGetter, JWKS


class Cognito(TokenVerifier):
    """
    Verify access token of AWS Cognito
    """

    scope_key = "cognito:groups"

    def __init__(self, region: str, userPoolId: str, *args, **kwargs):
        url = f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json"
        jwks = JWKS.fromurl(url)
        super().__init__(jwks, *args, **kwargs)


class CognitoClaims(BaseModel):
    username: str = Field(alias="cognito:username")
    email: str = Field(None, alias="email")


class CognitoCurrentUser(TokenUserInfoGetter):
    """
    Verify ID token and get user info of AWS Cognito
    """

    user_info = CognitoClaims

    def __init__(self, region: str, userPoolId: str, *args, **kwargs):
        url = f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json"
        jwks = JWKS.fromurl(url)
        super().__init__(jwks, *args, **kwargs)
