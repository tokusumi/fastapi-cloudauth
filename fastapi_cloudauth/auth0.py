from pydantic import BaseModel, Field
from .base import TokenVerifier, TokenUserInfoGetter, JWKS


class Auth0(TokenVerifier):
    """
    Verify access token of auth0
    """

    scope_key = "scope"

    def __init__(self, domain: str, *args, **kwargs):
        url = f"https://{domain}/.well-known/jwks.json"
        jwks = JWKS.fromurl(url)
        super().__init__(jwks, *args, **kwargs)


class Auth0Claims(BaseModel):
    username: str = Field(alias="name")
    email: str = Field(None, alias="email")


class Auth0CurrentUser(TokenUserInfoGetter):
    """
    Verify ID token and get user info of Auth0
    """

    user_info = Auth0Claims

    def __init__(self, domain: str, *args, **kwargs):
        url = f"https://{domain}/.well-known/jwks.json"
        jwks = JWKS.fromurl(url)
        super().__init__(jwks, *args, **kwargs)
