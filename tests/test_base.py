import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from fastapi_cloudauth.base import JWKS, TokenUserInfoGetter, TokenVerifier


@pytest.mark.unittest
def test_raise_error_invalid_set_scope():
    # scope_key is not declaired
    token_verifier = TokenVerifier(jwks=JWKS(keys=[]))
    with pytest.raises(AttributeError):
        # raise AttributeError for invalid instanse attributes wrt scope
        token_verifier.scope("read:test")


@pytest.mark.unittest
def test_return_instance_with_scope():
    # scope method return new instance to give it for Depends.
    verifier = TokenVerifier(jwks=JWKS(keys=[]))
    # must set scope_key (Inherit TokenVerifier and override scope_key attribute)
    scope_key = "dummy key"
    verifier.scope_key = scope_key

    scope_name = "required-scope"
    obj = verifier.scope(scope_name)
    assert isinstance(obj, TokenVerifier)
    assert obj.scope_key == scope_key, "scope_key mustn't be cleared."
    assert obj.scope_name == scope_name, "Must set scope_name in returned instanse."
    assert obj.jwks_to_key == verifier.jwks_to_key, "return cloned objects"
    assert obj.auto_error == verifier.auto_error, "return cloned objects"


@pytest.mark.unittest
@pytest.mark.parametrize(
    "scopes",
    [
        "user-assigned-scope",
        "xxx:xxx user-assigned-scope yyy:yyy",
        ["xxx:xxx", "user-assigned-scope", "yyy:yyy"],
    ],
)
def test_validation_scope(mocker, scopes):
    mocker.patch(
        "fastapi_cloudauth.base.jwt.get_unverified_claims",
        return_value={"dummy key": scopes},
    )
    verifier = TokenVerifier(jwks=JWKS(keys=[]))
    scope_key = "dummy key"
    verifier.scope_key = scope_key

    scope_name = "user-assigned-scope"
    obj = verifier.scope(scope_name)
    assert obj.verify_scope(HTTPAuthorizationCredentials(scheme="", credentials=""))

    scope_name = "user-assigned-scope-invalid"
    obj = verifier.scope(scope_name)
    with pytest.raises(HTTPException):
        obj.verify_scope(HTTPAuthorizationCredentials(scheme="", credentials=""))

    obj.auto_error = False
    assert not obj.verify_scope(HTTPAuthorizationCredentials(scheme="", credentials=""))


@pytest.mark.unittest
def test_forget_def_user_info():
    with pytest.raises(AttributeError):
        TokenUserInfoGetter()
