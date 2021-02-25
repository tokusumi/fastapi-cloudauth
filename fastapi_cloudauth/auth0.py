from typing import Any, Optional

from pydantic import BaseModel, Field

from .base import ScopedAuth, UserInfoAuth
from .verification import JWKS


class Auth0(ScopedAuth):
    """
    Verify access token of auth0
    """

    user_info = None

    def __init__(
        self,
        domain: str,
        scope_key: Optional[str] = "permissions",
        auto_error: bool = True,
    ):
        url = f"https://{domain}/.well-known/jwks.json"
        jwks = JWKS.fromurl(url)
        super().__init__(
            jwks, scope_key=scope_key, auto_error=auto_error,
        )


class Auth0Claims(BaseModel):
    username: str = Field(alias="name")
    email: str = Field(None, alias="email")


class Auth0CurrentUser(UserInfoAuth):
    """
    Verify ID token and get user info of Auth0
    """

    user_info = Auth0Claims

    def __init__(
        self, domain: str, *args: Any, **kwargs: Any,
    ):
        url = f"https://{domain}/.well-known/jwks.json"
        jwks = JWKS.fromurl(url)
        super().__init__(jwks, *args, user_info=self.user_info, **kwargs)
