from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any, Dict, Optional, Type, Union

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt  # type: ignore
from pydantic import BaseModel
from pydantic.error_wrappers import ValidationError
from starlette import status

from fastapi_cloudauth.messages import NOT_AUTHENTICATED, NOT_VALIDATED_CLAIMS
from fastapi_cloudauth.verification import (
    JWKS,
    JWKsVerifier,
    ScopedJWKsVerifier,
    Verifier,
)


class CloudAuth(ABC):
    @property
    @abstractmethod
    def verifier(self) -> Verifier:
        """Composite Verifier class to verify jwt in HTTPAuthorizationCredentials"""
        ...  # pragma: no cover

    @verifier.setter
    def verifier(self, instance: Verifier) -> None:
        ...  # pragma: no cover

    @abstractmethod
    async def call(self, http_auth: HTTPAuthorizationCredentials) -> Any:
        """Define postprocess for verified token"""
        ...  # pragma: no cover

    def clone(self, instance: "CloudAuth") -> "CloudAuth":
        """create clone instanse"""
        # In some case, Verifier can't pickle (deepcopy).
        # Tempolary put it aside to deepcopy. Then, undo it at the last line.
        if not isinstance(instance, CloudAuth):
            raise TypeError(
                "Only subclass of CloudAuth can be cloned"
            )  # pragma: no cover

        _verifier = instance.verifier
        instance.verifier = None  # type: ignore
        clone = deepcopy(instance)
        clone.verifier = _verifier.clone(_verifier)
        instance.verifier = _verifier
        return clone

    async def __call__(
        self,
        http_auth: Optional[HTTPAuthorizationCredentials] = Depends(
            HTTPBearer(auto_error=False)
        ),
    ) -> Any:
        """User access/ID-token verification Shortcut to pass it into dependencies.
        Use as (`auth` is this instanse and `app` is fastapi.FastAPI instanse):
        ```
        from fastapi import Depends

        @app.get("/", dependencies=[Depends(auth)])
        def api():
            return "hello"
        ```
        """
        if http_auth is None:
            if self.verifier.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail=NOT_AUTHENTICATED
                )
            else:
                return None

        is_verified = self.verifier.verify_token(http_auth)
        if not is_verified:
            return None

        return await self.call(http_auth)


class UserInfoAuth(CloudAuth):
    """
    Verify `ID token` and extract user information
    """

    user_info: Optional[Type[BaseModel]] = None

    def __init__(
        self,
        jwks: JWKS,
        *,
        user_info: Optional[Type[BaseModel]] = None,
        auto_error: bool = True,
        **kwargs: Any
    ) -> None:

        self.user_info = user_info
        self.auto_error = auto_error
        self._verifier = JWKsVerifier(jwks, auto_error=self.auto_error)

    @property
    def verifier(self) -> JWKsVerifier:
        return self._verifier

    @verifier.setter
    def verifier(self, verifier: JWKsVerifier) -> None:
        self._verifier = verifier

    def _clone(self) -> "UserInfoAuth":
        cloned = super().clone(self)
        if isinstance(cloned, UserInfoAuth):
            return cloned
        raise NotImplementedError  # pragma: no cover

    def claim(self, schema: Optional[Type[BaseModel]] = None) -> "UserInfoAuth":
        """User verification and validation shortcut to pass it into app arguments.
        Use as (`auth` is this instanse and `app` is fastapi.FastAPI instanse):
        ```
        from fastapi import Depends
        from pydantic import BaseModel

        class CustomClaim(BaseModel):
            sub: str

        @app.get("/")
        def api(user: CustomClaim = Depends(auth.claim(CustomClaim))):
            return CustomClaim
        ```
        """
        clone = self._clone()
        clone.user_info = schema
        return clone

    async def call(
        self, http_auth: HTTPAuthorizationCredentials
    ) -> Optional[Union[BaseModel, Dict[str, Any]]]:
        """Get current user and verification with ID-token Shortcut.
        Use as (`Auth` is this subclass, `auth` is `Auth` instanse and `app` is fastapi.FastAPI instanse):
        ```
        from fastapi import Depends

        @app.get("/")
        def api(current_user: Auth = Depends(auth)):
            return current_user
        ```
        """
        claims: Dict[str, Any] = jwt.get_unverified_claims(http_auth.credentials)

        if not self.user_info:
            return claims

        try:
            current_user = self.user_info.parse_obj(claims)
            return current_user
        except ValidationError:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail=NOT_VALIDATED_CLAIMS,
                )
            else:
                return None


class ScopedAuth(CloudAuth):
    """
    Verify `Access token` and authorize it based on scope (or groups)
    """

    _scope_key: Optional[str] = None
    user_info: Optional[Type[BaseModel]] = None

    def __init__(
        self,
        jwks: JWKS,
        user_info: Optional[Type[BaseModel]] = None,
        scope_name: Optional[str] = None,
        scope_key: Optional[str] = None,
        auto_error: bool = True,
    ):
        self.user_info = user_info
        self.auto_error = auto_error
        self._scope_name = scope_name
        if scope_key:
            self._scope_key = scope_key

        self._verifier = ScopedJWKsVerifier(
            jwks,
            scope_name=self._scope_name,
            scope_key=self._scope_key,
            auto_error=self.auto_error,
        )

    @property
    def verifier(self) -> ScopedJWKsVerifier:
        return self._verifier

    @verifier.setter
    def verifier(self, verifier: ScopedJWKsVerifier) -> None:
        self._verifier = verifier

    @property
    def scope_key(self) -> Optional[str]:
        return self._scope_key

    @scope_key.setter
    def scope_key(self, key: Optional[str]) -> None:
        self._scope_key = key
        self._verifier.scope_key = key

    @property
    def scope_name(self) -> Optional[str]:
        return self._scope_name

    @scope_name.setter
    def scope_name(self, name: Optional[str]) -> None:
        self._scope_name = name
        self._verifier.scope_name = name

    def _clone(self) -> "ScopedAuth":
        cloned = super().clone(self)
        if isinstance(cloned, ScopedAuth):
            return cloned
        raise NotImplementedError  # pragma: no cover

    def scope(self, scope_name: str) -> "ScopedAuth":
        """User-SCOPE verification Shortcut to pass it into dependencies.
        Use as (`auth` is this instanse and `app` is fastapi.FastAPI instanse):
        ```
        from fastapi import Depends

        @app.get("/", dependencies=[Depends(auth.scope("allowed scope"))])
        def api():
            return "hello"
        ```
        """
        clone = self._clone()
        clone.scope_name = scope_name
        if not clone.scope_key:
            raise AttributeError("declaire scope_key to set scope")
        return clone

    def claim(self, schema: Optional[Type[BaseModel]] = None) -> "ScopedAuth":
        """User verification and validation shortcut to pass it into app arguments.
        Use as (`auth` is this instanse and `app` is fastapi.FastAPI instanse):
        ```
        from fastapi import Depends
        from pydantic import BaseModel

        class CustomClaim(BaseModel):
            sub: str

        @app.get("/")
        def api(user: CustomClaim = Depends(auth.claim(CustomClaim))):
            return CustomClaim
        ```
        """
        clone = self._clone()
        clone.user_info = schema
        return clone

    async def call(
        self, http_auth: HTTPAuthorizationCredentials
    ) -> Optional[Union[Dict[str, Any], BaseModel, bool]]:
        """User access-token verification Shortcut to pass it into dependencies.
        Use as (`auth` is this instanse and `app` is fastapi.FastAPI instanse):
        ```
        from fastapi import Depends

        @app.get("/", dependencies=[Depends(auth)])
        def api():
            return "hello"
        ```
        """

        claims: Dict[str, Any] = jwt.get_unverified_claims(http_auth.credentials)

        if not self.user_info:
            return claims

        try:
            current_user = self.user_info.parse_obj(claims)
            return current_user
        except ValidationError:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail=NOT_VALIDATED_CLAIMS,
                )
            else:
                return None
