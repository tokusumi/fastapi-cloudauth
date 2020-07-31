from pydantic.main import BaseModel
from .base import TokenVerifier, TokenUserInfoGetter, JWKS


class Auth0(TokenVerifier):
    """
    Verify access token of auth0
    """

    def __init__(self, domain: str, *args, **kwargs):
        url = f"https://{domain}/.well-known/jwks.json"
        jwks = JWKS.fromurl(url)
        super().__init__(jwks, *args, **kwargs)

