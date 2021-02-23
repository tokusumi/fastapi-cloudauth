import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from fastapi_cloudauth.base import UserInfoAuth, ScopedAuth
from fastapi_cloudauth.verification import JWKS


@pytest.mark.unittest
def test_raise_error_invalid_set_scope():
    # scope_key is not declaired
    token_verifier = ScopedAuth(jwks=JWKS(keys=[]))
    with pytest.raises(AttributeError):
        # raise AttributeError for invalid instanse attributes wrt scope
        token_verifier.scope("read:test")


@pytest.mark.unittest
def test_return_instance_with_scope():
    # scope method return new instance to give it for Depends.
    verifier = ScopedAuth(jwks=JWKS(keys=[]))
    # must set scope_key (Inherit ScopedAuth and override scope_key attribute)
    scope_key = "dummy key"
    verifier.scope_key = scope_key

    scope_name = "required-scope"
    obj = verifier.scope(scope_name)
    assert isinstance(obj, ScopedAuth)
    assert obj.scope_key == scope_key, "scope_key mustn't be cleared."
    assert obj.scope_name == scope_name, "Must set scope_name in returned instanse."
    assert (
        obj.verifier._jwks_to_key == verifier.verifier._jwks_to_key
    ), "return cloned objects"
    assert (
        obj.verifier.auto_error == verifier.verifier.auto_error
    ), "return cloned objects"


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
        "fastapi_cloudauth.verification.jwt.get_unverified_claims",
        return_value={"dummy key": scopes},
    )
    verifier = ScopedAuth(jwks=JWKS(keys=[]))
    scope_key = "dummy key"
    verifier.scope_key = scope_key

    scope_name = "user-assigned-scope"
    obj = verifier.scope(scope_name)
    assert obj.verifier._verify_scope(
        HTTPAuthorizationCredentials(scheme="", credentials="")
    )

    scope_name = "user-assigned-scope-invalid"
    obj = verifier.scope(scope_name)
    with pytest.raises(HTTPException):
        obj.verifier._verify_scope(
            HTTPAuthorizationCredentials(scheme="", credentials="")
        )

    obj.verifier.auto_error = False
    assert not obj.verifier._verify_scope(
        HTTPAuthorizationCredentials(scheme="", credentials="")
    )


@pytest.mark.unittest
@pytest.mark.asyncio
async def test_forget_def_user_info():
    get_current_user = UserInfoAuth(jwks=JWKS(keys=[]))

    get_current_user.user_info = None
    dummy_http_auth = HTTPAuthorizationCredentials(
        scheme="a", credentials="aaaaaaaaaaaaaaaa"
    )
    res = await get_current_user.call(dummy_http_auth)
    assert res is None
