from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt
from starlette.status import HTTP_401_UNAUTHORIZED

from fastapi_cloudauth import messages
from fastapi_cloudauth.verification import JWKS, JWKsVerifier, ScopedJWKsVerifier

from .helpers import _assert_verifier, _assert_verifier_no_error


@pytest.mark.unittest
def test_malformed_token_handling():
    http_auth_with_malformed_token = HTTPAuthorizationCredentials(
        scheme="a", credentials="malformed-token",
    )

    verifier = JWKsVerifier(jwks=JWKS(keys=[]))
    with pytest.raises(HTTPException):
        verifier._get_publickey(http_auth_with_malformed_token)
    with pytest.raises(HTTPException):
        verifier.verify_token(http_auth_with_malformed_token)

    verifier = JWKsVerifier(jwks=JWKS(keys=[]), auto_error=False)
    assert not verifier._get_publickey(http_auth_with_malformed_token)
    assert not verifier.verify_token(http_auth_with_malformed_token)

    verifier = ScopedJWKsVerifier(jwks=JWKS(keys=[]))
    with pytest.raises(HTTPException):
        verifier._verify_scope(http_auth_with_malformed_token)
    with pytest.raises(HTTPException):
        verifier.verify_token(http_auth_with_malformed_token)

    verifier = ScopedJWKsVerifier(jwks=JWKS(keys=[]), auto_error=False)
    assert not verifier._verify_scope(http_auth_with_malformed_token)
    assert not verifier.verify_token(http_auth_with_malformed_token)


@pytest.mark.unittest
def test_verify_token():
    verifier = JWKsVerifier(jwks=JWKS(keys=[]))
    verifier_no_error = JWKsVerifier(jwks=JWKS(keys=[]), auto_error=False)

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
