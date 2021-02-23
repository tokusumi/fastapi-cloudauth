from typing import Generic, List, Dict, Optional, Any, Type, TypeVar
from copy import deepcopy
from abc import ABC, abstractmethod
from jose import jwt  # type: ignore
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from pydantic.error_wrappers import ValidationError
from starlette import status

from fastapi_cloudauth.verification import (
    Verifier,
    ScopedJWKsVerifier,
    JWKsVerifier,
    JWKS,
)
from fastapi_cloudauth.messages import (
    NOT_AUTHENTICATED,
    NO_PUBLICKEY,
    NOT_VERIFIED,
    SCOPE_NOT_MATCHED,
    NOT_VALIDATED_CLAIMS,
)

T = TypeVar("T")


class CloudAuth(ABC):
    @property
    @abstractmethod
    def verifier(self) -> Verifier:
        """Composite Verifier class to verify jwt in HTTPAuthorizationCredentials"""
        ...

    @verifier.setter
    def verifier(self, instance: Verifier) -> None:
        ...

    @abstractmethod
    async def call(self, http_auth: HTTPAuthorizationCredentials) -> Any:
        """Define postprocess for verified token"""
        ...

    def clone(self, instance: T) -> T:
        """create clone instanse"""
        # In some case, Verifier can't pickle (deepcopy).
        # Tempolary put it aside to deepcopy. Then, undo it at the last line.
        if not isinstance(instance, CloudAuth):
            raise TypeError("Only subclass of CloudAuth can be cloned")

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

    async def call(
        self, http_auth: HTTPAuthorizationCredentials
    ) -> Optional[BaseModel]:
        """Get current user and verification with ID-token Shortcut.
        Use as (`Auth` is this subclass, `auth` is `Auth` instanse and `app` is fastapi.FastAPI instanse):
        ```
        from fastapi import Depends

        @app.get("/")
        def api(current_user: Auth = Depends(auth)):
            return current_user
        ```
        """
        if not self.user_info:
            return None

        claims = jwt.get_unverified_claims(http_auth.credentials)
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

    def __init__(
        self,
        jwks: JWKS,
        scope_name: Optional[str] = None,
        scope_key: Optional[str] = None,
        auto_error: bool = True,
    ):
        self._scope_name = scope_name
        if scope_key:
            self._scope_key = scope_key

        self._verifier = ScopedJWKsVerifier(
            jwks,
            scope_name=self._scope_name,
            scope_key=self._scope_key,
            auto_error=auto_error,
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
        return super().clone(self)

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

    async def call(self, http_auth: HTTPAuthorizationCredentials) -> Optional[bool]:
        """User access-token verification Shortcut to pass it into dependencies.
        Use as (`auth` is this instanse and `app` is fastapi.FastAPI instanse):
        ```
        from fastapi import Depends

        @app.get("/", dependencies=[Depends(auth)])
        def api():
            return "hello"
        ```
        """
        return True
