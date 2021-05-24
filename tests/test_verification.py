import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from fastapi_cloudauth.verification import JWKS, JWKsVerifier, ScopedJWKsVerifier


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
