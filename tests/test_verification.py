import asyncio
from datetime import datetime, timedelta
from email.utils import format_datetime, parsedate_to_datetime
from typing import Any, Dict, Optional

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt
from jose.backends.base import Key
from requests.models import Response
from starlette.status import HTTP_401_UNAUTHORIZED

from fastapi_cloudauth import messages
from fastapi_cloudauth.verification import (
    JWKS,
    JWKsVerifier,
    Operator,
    ScopedJWKsVerifier,
)

from .helpers import _assert_verifier, _assert_verifier_no_error


@pytest.mark.unittest
@pytest.mark.asyncio
async def test_malformed_token_handling():
    http_auth_with_malformed_token = HTTPAuthorizationCredentials(
        scheme="a",
        credentials="malformed-token",
    )

    verifier = JWKsVerifier(jwks=JWKS.null())
    with pytest.raises(HTTPException):
        await verifier._get_publickey(http_auth_with_malformed_token)
    with pytest.raises(HTTPException):
        await verifier.verify_token(http_auth_with_malformed_token)

    verifier = JWKsVerifier(jwks=JWKS.null(), auto_error=False)
    assert not await verifier._get_publickey(http_auth_with_malformed_token)
    assert not await verifier.verify_token(http_auth_with_malformed_token)

    verifier = ScopedJWKsVerifier(jwks=JWKS.null())
    with pytest.raises(HTTPException):
        verifier._verify_scope(http_auth_with_malformed_token)
    with pytest.raises(HTTPException):
        await verifier.verify_token(http_auth_with_malformed_token)

    verifier = ScopedJWKsVerifier(jwks=JWKS.null(), auto_error=False)
    assert not verifier._verify_scope(http_auth_with_malformed_token)
    assert not await verifier.verify_token(http_auth_with_malformed_token)


@pytest.mark.asyncio
async def test_jwks_test_mode():
    # instantiate null jwks obj (no querying jwks)
    _jwks = JWKS.null()

    # instantiate fixed jwks obj (no querying jwks)
    dummy = Key(None, None)
    _jwks = JWKS(fixed_keys={"test": dummy})
    assert await _jwks.get_publickey("test") == dummy


class DummyResp(Response):
    def __init__(self, expires: datetime) -> None:
        super().__init__()
        self.headers["Expires"] = format_datetime(expires)

    @property
    def json(self):
        return lambda: {}


class DummyDecodeJWKS(JWKS):
    def _construct(self, jwks: Dict[str, Any]) -> Dict[str, Key]:
        return {}

    def _set_expiration(self, resp: Response) -> Optional[datetime]:
        expires_header = resp.headers.get("expires")
        return parsedate_to_datetime(expires_header)


def parse(t: datetime) -> datetime:
    return parsedate_to_datetime(format_datetime(t))


@pytest.mark.unittest
@pytest.mark.asyncio
async def test_refresh_jwks(mocker):
    too_short_exp = datetime.now()
    mocker.patch(
        "requests.get",
        return_value=DummyResp(too_short_exp),
    )
    _jwks = DummyDecodeJWKS(url="http://")

    # expires is stored
    assert _jwks.expires == parse(too_short_exp)

    # time goes...
    new_exp = too_short_exp + timedelta(days=10)
    mocker.patch(
        "requests.get",
        return_value=DummyResp(new_exp),
    )
    await _jwks.get_publickey("")
    # expired is refreshed
    assert parse(too_short_exp) != parse(new_exp)
    assert _jwks.expires == parse(new_exp)


class DummyDecodeCntJWKS(JWKS):
    def __init__(self, url: str = ""):
        self._counter = 0
        super().__init__(url=url)

    def _construct(self, jwks: Dict[str, Any]) -> Dict[str, Key]:
        asyncio.sleep(0.5)
        self._counter += 1
        return {"cnt": self._counter}

    def _set_expiration(self, resp: Response) -> Optional[datetime]:
        expires_header = resp.headers.get("expires")
        return parsedate_to_datetime(expires_header)


@pytest.mark.unittest
@pytest.mark.asyncio
async def test_refresh_jwks_multiple(mocker):
    too_short_exp = datetime.now()
    mocker.patch(
        "requests.get",
        return_value=DummyResp(too_short_exp),
    )
    _jwks = DummyDecodeCntJWKS(url="http://")

    # time goes...
    new_exp = too_short_exp + timedelta(days=10)
    mocker.patch(
        "requests.get",
        return_value=DummyResp(new_exp),
    )
    # multiple expired access
    res = await asyncio.gather(
        _jwks.get_publickey("cnt"),
        _jwks.get_publickey("cnt"),
        _jwks.get_publickey("cnt"),
    )
    # jwks was refreshed only at once (counter incremented once).
    # all three return publickey from refreshed jwks.
    assert list(res) == [2, 2, 2]


@pytest.mark.unittest
def test_verify_scope_exeption(mocker):
    mocker.patch(
        "fastapi_cloudauth.verification.jwt.get_unverified_claims",
        return_value={"dummy key": "read:test"},
    )
    scope_key = "dummy key"
    http_auth = HTTPAuthorizationCredentials(
        scheme="a",
        credentials="dummy-token",
    )

    # trivial scope
    verifier = ScopedJWKsVerifier(
        jwks=JWKS.null(), scope_key=scope_key, scope_name=None
    )
    assert verifier._verify_scope(http_auth)

    # invalid incoming scope format
    mocker.patch(
        "fastapi_cloudauth.verification.jwt.get_unverified_claims",
        return_value={"dummy key": 100},
    )
    verifier = ScopedJWKsVerifier(
        jwks=JWKS.null(), scope_key=scope_key, scope_name=["read:test"]
    )
    with pytest.raises(HTTPException):
        verifier._verify_scope(http_auth)
    # auto_error is False
    verifier = ScopedJWKsVerifier(
        jwks=JWKS.null(),
        scope_key=scope_key,
        scope_name=["read:test"],
        auto_error=False,
    )
    assert not verifier._verify_scope(http_auth)


@pytest.mark.unittest
@pytest.mark.parametrize(
    "scopes",
    ["xxx:xxx yyy:yyy", ["xxx:xxx", "yyy:yyy"]],
)
def test_scope_match_all(mocker, scopes):
    scope_key = "dummy key"
    http_auth = HTTPAuthorizationCredentials(
        scheme="a",
        credentials="dummy-token",
    )

    # check scope logic
    mocker.patch(
        "fastapi_cloudauth.verification.jwt.get_unverified_claims",
        return_value={"dummy key": scopes},
    )
    jwks = JWKS.null()

    # api scope < user scope
    verifier = ScopedJWKsVerifier(
        scope_name=["xxx:xxx"],
        jwks=jwks,
        scope_key=scope_key,
        auto_error=False,
    )
    assert verifier._verify_scope(http_auth)

    # api scope == user scope (in order)
    verifier = ScopedJWKsVerifier(
        scope_name=["xxx:xxx", "yyy:yyy"],
        jwks=jwks,
        scope_key=scope_key,
        auto_error=False,
    )
    assert verifier._verify_scope(http_auth)

    # api scope == user scope (disorder)
    verifier = ScopedJWKsVerifier(
        scope_name=["yyy:yyy", "xxx:xxx"],
        jwks=jwks,
        scope_key=scope_key,
        auto_error=False,
    )
    assert verifier._verify_scope(http_auth)

    # api scope > user scope
    verifier = ScopedJWKsVerifier(
        scope_name=["yyy:yyy", "xxx:xxx", "zzz:zzz"],
        jwks=jwks,
        scope_key=scope_key,
        auto_error=False,
    )
    assert not verifier._verify_scope(http_auth)


@pytest.mark.unittest
@pytest.mark.parametrize(
    "scopes",
    ["xxx:xxx yyy:yyy", ["xxx:xxx", "yyy:yyy"]],
)
def test_scope_match_any(mocker, scopes):
    scope_key = "dummy key"
    http_auth = HTTPAuthorizationCredentials(
        scheme="a",
        credentials="dummy-token",
    )

    # check scope logic
    mocker.patch(
        "fastapi_cloudauth.verification.jwt.get_unverified_claims",
        return_value={"dummy key": scopes},
    )
    jwks = JWKS.null()

    # api scope < user scope
    verifier = ScopedJWKsVerifier(
        scope_name=["xxx:xxx"],
        jwks=jwks,
        scope_key=scope_key,
        auto_error=False,
        op=Operator._any,
    )
    assert verifier._verify_scope(http_auth)

    # api scope == user scope (in order)
    verifier = ScopedJWKsVerifier(
        scope_name=["xxx:xxx", "yyy:yyy"],
        op=Operator._any,
        jwks=jwks,
        scope_key=scope_key,
        auto_error=False,
    )
    assert verifier._verify_scope(http_auth)

    # api scope == user scope (disorder)
    verifier = ScopedJWKsVerifier(
        scope_name=["yyy:yyy", "xxx:xxx"],
        op=Operator._any,
        jwks=jwks,
        scope_key=scope_key,
        auto_error=False,
    )
    assert verifier._verify_scope(http_auth)

    # api scope > user scope
    verifier = ScopedJWKsVerifier(
        scope_name=["yyy:yyy", "xxx:xxx", "zzz:zzz"],
        op=Operator._any,
        jwks=jwks,
        scope_key=scope_key,
        auto_error=False,
    )
    assert verifier._verify_scope(http_auth)

    # api scope ^ user scope
    verifier = ScopedJWKsVerifier(
        scope_name=["zzz:zzz"],
        op=Operator._any,
        jwks=jwks,
        scope_key=scope_key,
        auto_error=False,
    )
    assert not verifier._verify_scope(http_auth)


@pytest.mark.unittest
def test_verify_token():
    verifier = JWKsVerifier(jwks=JWKS.null())
    verifier_no_error = JWKsVerifier(jwks=JWKS.null(), auto_error=False)

    # correct
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow(),
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    verifier._verify_claims(HTTPAuthorizationCredentials(scheme="a", credentials=token))
    verifier_no_error._verify_claims(
        HTTPAuthorizationCredentials(scheme="a", credentials=token)
    )

    # token expired
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() - timedelta(hours=10),  # 10h before
            "iat": datetime.utcnow(),
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == messages.NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # token created at future
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow() + timedelta(hours=10),
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    e = _assert_verifier(token, verifier)
    assert e.status_code == HTTP_401_UNAUTHORIZED and e.detail == messages.NOT_VERIFIED
    _assert_verifier_no_error(token, verifier_no_error)

    # invalid format
    token = jwt.encode(
        {
            "sub": "dummy-ID",
            "exp": datetime.utcnow() + timedelta(hours=10),
            "iat": datetime.utcnow(),
        },
        "dummy_secret",
        headers={"alg": "HS256", "typ": "JWT", "kid": "dummy-kid"},
    )
    token = token.split(".")[0]
    e = _assert_verifier(token, verifier)
    assert (
        e.status_code == HTTP_401_UNAUTHORIZED
        and e.detail == messages.NOT_AUTHENTICATED
    )
    _assert_verifier_no_error(token, verifier_no_error)
