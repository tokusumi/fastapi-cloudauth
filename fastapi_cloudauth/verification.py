from abc import ABC, abstractmethod
from asyncio import Event
from calendar import timegm
from copy import deepcopy
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Type, Union

import requests
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt
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
    async def verify_token(self, http_auth: HTTPAuthorizationCredentials) -> bool:
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
    def __init__(
        self,
        url: str = "",
        fixed_keys: Optional[Dict[str, Key]] = None,
    ):
        """Handle the JSON Web Key Set (JWKS), query and refresh ...
        Args:
            url: Provider JWKS URL. See official doc for what you want to connect.
            fixed_keys: (For Test) Set fixed jwks. if passed not None, make it invalid connection between social provider
        """
        self.__url = url
        self.__fixed_keys = fixed_keys
        self.__keys: Dict[str, Key] = {}
        self.__expires: Optional[datetime] = None
        self.__refreshing = Event()
        self.__refreshing.set()
        if self.__fixed_keys is None:
            # query jwks from provider without mutex
            self._refresh_keys()

    async def get_publickey(self, kid: str) -> Optional[Key]:
        if self.__fixed_keys is not None:
            return self.__fixed_keys.get(kid)

        if self.__expires is not None:
            # Check expiration
            current_time = datetime.now(tz=self.__expires.tzinfo)
            if current_time >= self.__expires:
                await self.refresh_keys()

        return self.__keys.get(kid)

    async def refresh_keys(self) -> bool:
        """refresh jwks process"""
        if self.__refreshing.is_set():
            # refresh jwks
            # Ensure only one key refresh can happen at once.
            # This prevents a dogpile of requests the second the keys expire
            # from causing a bunch of refreshes (each one is an http request).
            self.__refreshing.clear()

            # Re-query the keys from provider
            self._refresh_keys()

            # Remove the lock.
            self.__refreshing.set()
        else:
            # Other task for refresh is still working.
            # Only wait for that to pick publickey from the latest JWKS.
            # (Now, this line is not reachable because current re-quering is not awaitable)
            await self.__refreshing.wait()

        return True

    def _refresh_keys(self) -> None:
        """Core refresh jwks process
        NOTE: Call this directly if you does not require mutex on refresh process
        """
        # Re-query the keys from provider.
        # NOTE (For Firebase Auth): The expires comes from an http header which is supposed to
        # be set to a time long before the keys are no longer in use.
        # This allows gradual roll-out of the keys and should prevent any
        # request from failing.
        # The only scenario which will result in failing requests is if
        # there are zero requests for the entire duration of the roll-out
        # (observed to be around 1 week), followed by a burst of multiple
        # requests at once.
        jwks_resp = requests.get(self.__url)

        # Reset the keys and the expiry date.
        self.__keys = self._construct(jwks_resp.json())
        self.__expires = self._set_expiration(jwks_resp)

    def _construct(self, jwks: Dict[str, Any]) -> Dict[str, Key]:
        raise NotImplementedError  # pragma: no cover

    def _set_expiration(self, resp: requests.Response) -> Optional[datetime]:
        return None

    @classmethod
    def null(cls: Type["JWKS"]) -> "JWKS":
        return cls(url="", fixed_keys={})

    @property
    def expires(self) -> Optional[datetime]:
        return self.__expires


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
        self._jwks = jwks
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

    async def _get_publickey(
        self, http_auth: HTTPAuthorizationCredentials
    ) -> Optional[Key]:
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
        publickey = await self._jwks.get_publickey(kid)
        if not publickey:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=NO_PUBLICKEY,
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
                options={
                    "verify_signature": False,
                    "verify_sub": False,
                    "verify_at_hash": False,
                },  # done
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

    async def verify_token(self, http_auth: HTTPAuthorizationCredentials) -> bool:
        # check the signature
        public_key = await self._get_publickey(http_auth)
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
        _jwks = instance._jwks
        instance._jwks = None  # type: ignore
        clone = deepcopy(instance)
        clone._jwks = _jwks
        instance._jwks = _jwks
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
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=SCOPE_NOT_MATCHED,
                )
            return False
        return True

    async def verify_token(self, http_auth: HTTPAuthorizationCredentials) -> bool:
        is_verified = await super().verify_token(http_auth)
        if not is_verified:
            return False

        if self.scope_name:
            is_verified_scope = self._verify_scope(http_auth)
            return is_verified_scope

        return True
