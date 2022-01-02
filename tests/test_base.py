import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel

from fastapi_cloudauth.base import ScopedAuth, UserInfoAuth
from fastapi_cloudauth.verification import JWKS


@pytest.mark.unittest
def test_raise_error_invalid_set_scope():
    # scope_key is not declaired
    token_verifier = ScopedAuth(jwks=JWKS.null())
    with pytest.raises(AttributeError):
        # raise AttributeError for invalid instanse attributes wrt scope
        token_verifier.scope("read:test")


@pytest.mark.unittest
def test_return_instance_with_scope():
    # scope method return new instance to give it for Depends.
    verifier = ScopedAuth(jwks=JWKS.null())
    # must set scope_key (Inherit ScopedAuth and override scope_key attribute)
    scope_key = "dummy key"
    verifier.scope_key = scope_key

    scope_name = "required-scope"
    obj = verifier.scope(scope_name)
    assert isinstance(obj, ScopedAuth)
    assert obj.scope_key == scope_key, "scope_key mustn't be cleared."
    assert obj.scope_name == [scope_name], "Must set scope_name in returned instanse."
    assert obj.verifier.scope_name == set(
        [scope_name]
    ), "Must convert scope name into set."
    assert obj.verifier._jwks == verifier.verifier._jwks, "return cloned objects"
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
    verifier = ScopedAuth(jwks=JWKS.null())
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
@pytest.mark.parametrize(
    "auth",
    [UserInfoAuth, ScopedAuth],
)
async def test_forget_def_user_info(auth):
    dummy_http_auth = HTTPAuthorizationCredentials(
        scheme="a",
        credentials="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Im5hbWUiLCJpYXQiOjE1MTYyMzkwMjJ9.3ZEDmhWNZWDbJDPDlZX_I3oaalNYXdoT-bKLxIxQK4U",
    )
    """If `.user_info` is None, return raw payload"""
    get_current_user = auth(jwks=JWKS.null())
    assert get_current_user.user_info is None
    res = await get_current_user.call(dummy_http_auth)
    assert res == {"sub": "1234567890", "name": "name", "iat": 1516239022}


@pytest.mark.unittest
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "auth",
    [UserInfoAuth, ScopedAuth],
)
async def test_assign_user_info(auth):
    """three way to set user info schema
    1. pass it to arguments when create instance
    2. call `.claim` method and pass it to that arguments
    3. assign with `=` statements
    """

    class SubSchema(BaseModel):
        sub: str

    class NameSchema(BaseModel):
        name: str

    class IatSchema(BaseModel):
        iat: int

    # authorized token
    dummy_http_auth = HTTPAuthorizationCredentials(
        scheme="a",
        credentials="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Im5hbWUiLCJpYXQiOjE1MTYyMzkwMjJ9.3ZEDmhWNZWDbJDPDlZX_I3oaalNYXdoT-bKLxIxQK4U",
    )

    user = auth(jwks=JWKS.null(), user_info=IatSchema)
    assert await user.call(dummy_http_auth) == IatSchema(iat=1516239022)

    assert await user.claim(SubSchema).call(dummy_http_auth) == SubSchema(
        sub="1234567890"
    )

    user.user_info = NameSchema
    assert await user.call(dummy_http_auth) == NameSchema(name="name")


@pytest.mark.unittest
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "auth",
    [UserInfoAuth, ScopedAuth],
)
async def test_extract_raw_user_info(auth):
    dummy_http_auth = HTTPAuthorizationCredentials(
        scheme="a",
        credentials="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Im5hbWUiLCJpYXQiOjE1MTYyMzkwMjJ9.3ZEDmhWNZWDbJDPDlZX_I3oaalNYXdoT-bKLxIxQK4U",
    )

    class NameSchema(BaseModel):
        name: str

    get_current_user = auth(jwks=JWKS.null(), user_info=NameSchema)
    get_current_user.user_info = None
    res = await get_current_user.call(dummy_http_auth)
    assert res == {"sub": "1234567890", "name": "name", "iat": 1516239022}

    get_current_user = auth(jwks=JWKS.null(), user_info=NameSchema)
    res = await get_current_user.claim(None).call(dummy_http_auth)
    assert res == {"sub": "1234567890", "name": "name", "iat": 1516239022}
