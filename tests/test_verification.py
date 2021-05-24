import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from fastapi_cloudauth.verification import (
    JWKS,
    JWKsVerifier,
    ScopedJWKsVerifier,
    Operator,
)


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
def test_verify_scope_exeption(mocker):
    mocker.patch(
        "fastapi_cloudauth.verification.jwt.get_unverified_claims",
        return_value={"dummy key": "read:test"},
    )
    scope_key = "dummy key"
    http_auth = HTTPAuthorizationCredentials(scheme="a", credentials="dummy-token",)

    # trivial scope
    verifier = ScopedJWKsVerifier(
        jwks=JWKS(keys=[]), scope_key=scope_key, scope_name=None
    )
    assert verifier._verify_scope(http_auth)

    # invalid incoming scope format
    mocker.patch(
        "fastapi_cloudauth.verification.jwt.get_unverified_claims",
        return_value={"dummy key": 100},
    )
    verifier = ScopedJWKsVerifier(
        jwks=JWKS(keys=[]), scope_key=scope_key, scope_name=["read:test"]
    )
    with pytest.raises(HTTPException):
        verifier._verify_scope(http_auth)
    # auto_error is False
    verifier = ScopedJWKsVerifier(
        jwks=JWKS(keys=[]),
        scope_key=scope_key,
        scope_name=["read:test"],
        auto_error=False,
    )
    assert not verifier._verify_scope(http_auth)


@pytest.mark.unittest
@pytest.mark.parametrize(
    "scopes", ["xxx:xxx yyy:yyy", ["xxx:xxx", "yyy:yyy"]],
)
def test_scope_match_all(mocker, scopes):
    scope_key = "dummy key"
    http_auth = HTTPAuthorizationCredentials(scheme="a", credentials="dummy-token",)

    # check scope logic
    mocker.patch(
        "fastapi_cloudauth.verification.jwt.get_unverified_claims",
        return_value={"dummy key": scopes},
    )
    jwks = JWKS(keys=[])

    # api scope < user scope
    verifier = ScopedJWKsVerifier(
        scope_name=["xxx:xxx"], jwks=jwks, scope_key=scope_key, auto_error=False,
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
    "scopes", ["xxx:xxx yyy:yyy", ["xxx:xxx", "yyy:yyy"]],
)
def test_scope_match_any(mocker, scopes):
    scope_key = "dummy key"
    http_auth = HTTPAuthorizationCredentials(scheme="a", credentials="dummy-token",)

    # check scope logic
    mocker.patch(
        "fastapi_cloudauth.verification.jwt.get_unverified_claims",
        return_value={"dummy key": scopes},
    )
    jwks = JWKS(keys=[])

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
