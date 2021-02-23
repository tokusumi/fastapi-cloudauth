from typing import List, Dict, Optional, Any, Type, T
import requests
from copy import deepcopy
from abc import ABC, abstractmethod
from jose import jwk, jwt  # type: ignore
from jose.utils import base64url_decode  # type: ignore
from jose.backends.base import Key  # type: ignore
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from pydantic.error_wrappers import ValidationError
from starlette import status

from fastapi_cloudauth.messages import (
    NOT_AUTHENTICATED,
    NO_PUBLICKEY,
    NOT_VERIFIED,
    SCOPE_NOT_MATCHED,
    NOT_VALIDATED_CLAIMS,
)


class Verifier(ABC):
    @property
    @abstractmethod
    def auto_error(self) -> bool:
        ...

    @abstractmethod
    def verify_token(self, http_auth: HTTPAuthorizationCredentials) -> bool:
        ...

    def clone(self, instance: T) -> T:
        """create clone instanse"""
        # In some case, Verifier can't pickle (deepcopy).
        # Tempolary put it aside to deepcopy. Then, undo it at the last line.
        if not isinstance(instance, Verifier):
            raise TypeError("Only subclass of Verifier can be cloned")

        clone = deepcopy(instance)
        return clone


class JWKS:
    keys: Dict[str, Key]

    def __init__(self, keys: Dict[str, Key]):
        self.keys = keys

    @classmethod
    def fromurl(cls, url: str) -> "JWKS":
        """
        get and parse json into jwks from endpoint as follows,
        https://xxx/.well-known/jwks.json
        """
        jwks = requests.get(url).json()

        jwks = {_jwk["kid"]: jwk.construct(_jwk) for _jwk in jwks.get("keys", [])}
        return cls(keys=jwks)

    @classmethod
    def firebase(cls, url: str) -> "JWKS":
        """
        get and parse json into jwks from endpoint for Firebase,
        """
        certs = requests.get(url).json()
        keys = {
            kid: jwk.construct(publickey, algorithm="RS256")
            for kid, publickey in certs.items()
        }
        return cls(keys=keys)


class JWKsVerifier(Verifier):
    def __init__(
        self, jwks: JWKS, auto_error: bool = True, *args: Any, **kwargs: Any
    ) -> None:
        """
        auto-error: if False, return payload as b'null' for invalid token.
        """
        self._jwks_to_key = jwks.keys
        self._auto_error = auto_error

    @property
    def auto_error(self) -> bool:
        return self._auto_error

    @auto_error.setter
    def auto_error(self, auto_error: bool) -> None:
        self._auto_error = auto_error

    def _get_publickey(self, http_auth: HTTPAuthorizationCredentials) -> Optional[Key]:
        token = http_auth.credentials
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail=NOT_AUTHENTICATED
                )
            else:
                return None
        publickey: Optional[Key] = self._jwks_to_key.get(kid)
        if not publickey:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail=NO_PUBLICKEY,
                )
            else:
                return None
        return publickey

    def verify_token(self, http_auth: HTTPAuthorizationCredentials) -> bool:
        public_key = self._get_publickey(http_auth)
        if not public_key:
            # error handling is included in self.get_publickey
            return False

        message, encoded_sig = http_auth.credentials.rsplit(".", 1)
        decoded_sig = base64url_decode(encoded_sig.encode())
        is_verified: bool = public_key.verify(message.encode(), decoded_sig)

        if not is_verified:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail=NOT_VERIFIED
                )

        return is_verified

    def clone(self, instance: "JWKsVerifier") -> "JWKsVerifier":
        _jwks_to_key = instance._jwks_to_key
        instance._jwks_to_key = {}
        clone = deepcopy(instance)
        clone._jwks_to_key = _jwks_to_key
        instance._jwks_to_key = _jwks_to_key
        return clone


class ScopedJWKsVerifier(JWKsVerifier):
    def __init__(
        self,
        jwks: JWKS,
        scope_name: Optional[str] = None,
        scope_key: Optional[str] = None,
        auto_error: bool = True,
        *args: Any,
        **kwargs: Any
    ) -> None:
        """
        auto-error: if False, return payload as b'null' for invalid token.
        """
        super().__init__(jwks, auto_error=auto_error)
        self.scope_name = scope_name
        self.scope_key = scope_key

    def _verify_scope(self, http_auth: HTTPAuthorizationCredentials) -> bool:
        claims = jwt.get_unverified_claims(http_auth.credentials)
        scopes = claims.get(self.scope_key)
        if isinstance(scopes, str):
            scopes = {scope.strip() for scope in scopes.split()}
        if scopes is None or self.scope_name not in scopes:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail=SCOPE_NOT_MATCHED,
                )
            return False
        return True

    def verify_token(self, http_auth: HTTPAuthorizationCredentials) -> bool:
        is_verified = super().verify_token(http_auth)
        if not is_verified:
            return False

        if self.scope_name:
            is_verified_scope = self._verify_scope(http_auth)
            return is_verified_scope

        return True
