import pytest

from fastapi_cloudauth.base import JWKS, TokenUserInfoGetter, TokenVerifier


def test_raise_error_invalid_set_scope():
    # scope_key is not declaired
    token_verifier = TokenVerifier(jwks=JWKS(keys=[]))
    try:
        raised = False
        token_verifier.scope("read:test")
    except AttributeError:
        raised = True
    assert raised, "raise AttributeError for invalid instanse attributes wrt scope"


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


def test_forget_def_user_info():
    with pytest.raises(AttributeError):
        TokenUserInfoGetter()
