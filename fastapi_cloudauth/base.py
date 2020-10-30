from typing import List, Dict, Optional, Any, Type
import requests
from copy import deepcopy
from jose import jwk, jwt
from jose.utils import base64url_decode
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from pydantic.error_wrappers import ValidationError
from starlette import status


class JWKS(BaseModel):
    keys: List[Dict[str, Any]]

    @classmethod
    def fromurl(cls, url: str):
        """
        get and parse json into jwks from endpoint as follows,
        https://xxx/.well-known/jwks.json
        """
        return cls.parse_obj(requests.get(url).json())


class BaseTokenVerifier:
    def __init__(self, jwks: JWKS, auto_error: bool = True, *args, **kwargs):
        """
        auto-error: if False, return payload as b'null' for invalid token.
        """
        self.jwks_to_key = {_jwk["kid"]: jwk.construct(_jwk) for _jwk in jwks.keys}
        self.scope_name: Optional[str] = None
        self.auto_error = auto_error

    def clone(self):
        """create clone instanse"""
        # In some case, self.jwks_to_key can't pickle (deepcopy).
        # Tempolary put it aside to deepcopy. Then, undo it at the last line.
        jwks_to_key = self.jwks_to_key
        self.jwks_to_key = {}
        clone = deepcopy(self)
        clone.jwks_to_key = jwks_to_key

        # undo original instanse
        self.jwks_to_key = jwks_to_key
        return clone

    def get_publickey(self, http_auth: HTTPAuthorizationCredentials):
        token = http_auth.credentials
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            else:
                return None
        publickey = self.jwks_to_key.get(kid)
        if not publickey:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="JWK public Attribute not found",
                )
            else:
                return None
        return publickey

    def verify_token(self, http_auth: HTTPAuthorizationCredentials) -> bool:
        public_key = self.get_publickey(http_auth)
        if not public_key:
            # error handling is included in self.get_publickey
            return False

        message, encoded_sig = http_auth.credentials.rsplit(".", 1)
        decoded_sig = base64url_decode(encoded_sig.encode())
        is_verified = public_key.verify(message.encode(), decoded_sig)

        if not is_verified:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Not verified"
                )

        return is_verified


class TokenVerifier(BaseTokenVerifier):
    """
    Verify `Access token` and authorize it based on scope (or groups)
    """

    scope_key: Optional[str] = None

    def scope(self, scope_name: str):
        """User-SCOPE verification Shortcut to pass it into dependencies.
        Use as (`auth` is this instanse and `app` is fastapi.FastAPI instanse):
        ```
        from fastapi import Depends

        @app.get("/", dependencies=[Depends(auth.scope("allowed scope"))])
        def api():
            return "hello"
        ```
        """
        clone = self.clone()
        clone.scope_name = scope_name
        if not clone.scope_key:
            raise AttributeError("declaire scope_key to set scope")
        return clone

    def verify_scope(self, http_auth: HTTPAuthorizationCredentials) -> bool:
        claims = jwt.get_unverified_claims(http_auth.credentials)
        scopes = claims.get(self.scope_key)
        if isinstance(scopes, str):
            scopes = {scope.strip() for scope in scopes.split()}
        if scopes is None or self.scope_name not in scopes:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Scope not matched. {claims}",
                )
            return False
        return True

    async def __call__(
        self, http_auth: HTTPAuthorizationCredentials = Depends(HTTPBearer())
    ) -> Optional[bool]:
        """User access-token verification Shortcut to pass it into dependencies.
        Use as (`auth` is this instanse and `app` is fastapi.FastAPI instanse):
        ```
        from fastapi import Depends

        @app.get("/", dependencies=[Depends(auth)])
        def api():
            return "hello"
        ```
        """
        is_verified = self.verify_token(http_auth)
        if not is_verified:
            return None

        if self.scope_name:
            is_verified_scope = self.verify_scope(http_auth)
            if not is_verified_scope:
                return None

        return True


class TokenUserInfoGetter(BaseTokenVerifier):
    """
    Verify `ID token` and extract user information
    """

    user_info: Type[BaseModel]

    def __init__(self, *args, **kwargs):
        try:
            self.user_info
        except AttributeError:
            raise AttributeError(
                "must assign custom pydantic.BaseModel into class attributes `user_info`"
            )
        super().__init__(*args, **kwargs)

    async def __call__(
        self, http_auth: HTTPAuthorizationCredentials = Depends(HTTPBearer())
    ) -> Optional[Type[BaseModel]]:
        """Get current user and verification with ID-token Shortcut.
        Use as (`Auth` is this subclass, `auth` is `Auth` instanse and `app` is fastapi.FastAPI instanse):
        ```
        from fastapi import Depends

        @app.get("/")
        def api(current_user: Auth = Depends(auth)):
            return current_user
        ```
        """
        is_verified = self.verify_token(http_auth)
        if not is_verified:
            return None

        claims = jwt.get_unverified_claims(http_auth.credentials)
        try:
            current_user = self.user_info.parse_obj(claims)
            return current_user
        except ValidationError:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Validation Error for Claims",
                )
            else:
                return None
