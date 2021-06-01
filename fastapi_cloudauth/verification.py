from abc import ABC, abstractmethod
from calendar import timegm
from copy import deepcopy
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import requests
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwk, jwt
from jose.backends.base import Key
from jose.exceptions import JWTError
from jose.utils import base64url_decode
from starlette import status

from fastapi_cloudauth.messages import (
    NO_PUBLICKEY,
    NOT_AUTHENTICATED,
    NOT_VERIFIED,
    SCOPE_NOT_MATCHED,
)


class Verifier(ABC):
    @property
    @abstractmethod
    def auto_error(self) -> bool:
        ...  # pragma: no cover

    @abstractmethod
    def verify_token(self, http_auth: HTTPAuthorizationCredentials) -> bool:
        ...  # pragma: no cover

    @abstractmethod
    def clone(self, instance: "Verifier") -> "Verifier":
        """create clone instanse"""
        ...  # pragma: no cover


class ExtraVerifier(ABC):
    @abstractmethod
    def __call__(self, claims: Dict[str, str], auto_error: bool = True) -> bool:
        ...  # pragma: no cover


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
        self,
        jwks: JWKS,
        audience: Optional[Union[str, List[str]]] = None,
        issuer: Optional[str] = None,
        auto_error: bool = True,
        *args: Any,
        extra: Optional[ExtraVerifier] = None,
        **kwargs: Any
    ) -> None:
        """
        auto-error: if False, return payload as b'null' for invalid token.
        """
        self._jwks_to_key = jwks.keys
        self._auto_error = auto_error
        self._extra_verifier = extra
        self._aud = audience
        self._iss = issuer

    @property
    def auto_error(self) -> bool:
        return self._auto_error

    @auto_error.setter
    def auto_error(self, auto_error: bool) -> None:
        self._auto_error = auto_error

    def _get_publickey(self, http_auth: HTTPAuthorizationCredentials) -> Optional[Key]:
        token = http_auth.credentials

        try:
            header = jwt.get_unverified_header(token)
        except JWTError as e:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=NOT_AUTHENTICATED
                ) from e
            else:
                return None

        kid = header.get("kid")
        if not kid:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=NOT_AUTHENTICATED
                )
            else:
                return None
        publickey: Optional[Key] = self._jwks_to_key.get(kid)
        if not publickey:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=NO_PUBLICKEY,
                )
            else:
                return None
        return publickey

    def _verify_claims(self, http_auth: HTTPAuthorizationCredentials) -> bool:
        is_verified = False
        try:
            # check the expiration, issuer
            is_verified = jwt.decode(
                http_auth.credentials,
                "",
                audience=self._aud,
                issuer=self._iss,
                options={"verify_signature": False, "verify_sub": False},  # done
            )
        except jwt.ExpiredSignatureError as e:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=NOT_VERIFIED
                ) from e
            return False
        except jwt.JWTClaimsError as e:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=NOT_VERIFIED
                ) from e
            return False
        except JWTError as e:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=NOT_AUTHENTICATED
                ) from e
            else:
                return False

        claims = jwt.get_unverified_claims(http_auth.credentials)

        # iat validation
        if claims.get("iat"):
            iat = int(claims["iat"])
            now = timegm(datetime.utcnow().utctimetuple())
            if now < iat:
                if self.auto_error:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED, detail=NOT_VERIFIED
                    )
                return False

        if self._extra_verifier:
            # check extra claims validation
            is_verified = self._extra_verifier(
                claims=claims, auto_error=self.auto_error
            )

        return is_verified

    def verify_token(self, http_auth: HTTPAuthorizationCredentials) -> bool:
        # check the signature
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
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=NOT_VERIFIED
                )
            return False
        # check the standard claims
        is_verified = self._verify_claims(http_auth)

        return is_verified

    def clone(self, instance: "JWKsVerifier") -> "JWKsVerifier":  # type: ignore[override]
        _jwks_to_key = instance._jwks_to_key
        instance._jwks_to_key = {}
        clone = deepcopy(instance)
        clone._jwks_to_key = _jwks_to_key
        instance._jwks_to_key = _jwks_to_key
        return clone


class Operator(Enum):
    _all = "all"
    _any = "any"


class ScopedJWKsVerifier(JWKsVerifier):
    def __init__(
        self,
        jwks: JWKS,
        audience: Optional[Union[str, List[str]]] = None,
        issuer: Optional[str] = None,
        scope_key: Optional[str] = None,
        scope_name: Optional[List[str]] = None,
        op: Operator = Operator._all,
        auto_error: bool = True,
        extra: Optional[ExtraVerifier] = None,
        *args: Any,
        **kwargs: Any
    ) -> None:
        """
        auto-error: if False, return payload as b'null' for invalid token.
        """
        super().__init__(
            jwks, auto_error=auto_error, extra=extra, audience=audience, issuer=issuer
        )
        self.scope_name = None if not scope_name else set(scope_name)
        self.scope_key = scope_key
        self.op = op

    def clone(self, instance: "ScopedJWKsVerifier") -> "ScopedJWKsVerifier":  # type: ignore[override]
        cloned = super().clone(instance)
        if isinstance(cloned, ScopedJWKsVerifier):
            return cloned
        raise NotImplementedError  # pragma: no cover

    def _verify_scope(self, http_auth: HTTPAuthorizationCredentials) -> bool:
        try:
            claims = jwt.get_unverified_claims(http_auth.credentials)
        except JWTError as e:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail=NOT_AUTHENTICATED
                ) from e
            else:
                return False

        scopes = claims.get(self.scope_key)
        if self.scope_name is None:
            # scope is not required
            return True

        matched = True
        if isinstance(scopes, str):
            scopes = {scope.strip() for scope in scopes.split()}
        else:
            try:
                scopes = set(scopes)
            except TypeError:
                matched = False
        if matched:
            if self.op == Operator._any:
                # any
                matched = len(self.scope_name & scopes) > 0
            else:
                # all
                matched = self.scope_name.issubset(scopes)
        if not matched:
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
