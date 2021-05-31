from typing import Any, Dict, Optional, Set

from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field
from starlette import status

from .base import ScopedAuth, UserInfoAuth
from .messages import NOT_VERIFIED
from .verification import JWKS, ExtraVerifier


class Cognito(ScopedAuth):
    """
    Verify access token of AWS Cognito
    """

    user_info = None

    def __init__(
        self,
        region: str,
        userPoolId: str,
        client_id: str,
        scope_key: Optional[str] = "cognito:groups",
        auto_error: bool = True,
    ):
        url = f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json"
        jwks = JWKS.fromurl(url)
        super().__init__(
            jwks,
            audience=client_id,
            issuer=f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
            scope_key=scope_key,
            auto_error=auto_error,
            extra=CognitoExtraVerifier(
                client_id=client_id,
                issuer=f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
                token_use={"access"},
            ),
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
        self, region: str, userPoolId: str, client_id: str, *args: Any, **kwargs: Any,
    ):
        url = f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json"
        jwks = JWKS.fromurl(url)
        super().__init__(
            jwks,
            user_info=self.user_info,
            audience=client_id,
            issuer=f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
            extra=CognitoExtraVerifier(
                client_id=client_id,
                issuer=f"https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
                token_use={"id"},
            ),
            *args,
            **kwargs,
        )


class CognitoExtraVerifier(ExtraVerifier):
    def __init__(self, client_id: str, issuer: str, token_use: Set[str]):
        self._aud = client_id
        self._iss = issuer
        self._tu = token_use

    def __call__(self, claims: Dict[str, str], auto_error: bool = True) -> bool:
        # check token_use
        if claims.get("token_use"):
            if claims["token_use"] not in self._tu:
                if auto_error:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED, detail=NOT_VERIFIED
                    )
                return False
        return True
