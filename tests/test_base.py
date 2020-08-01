from fastapi_auth.base import JWKS, TokenUserInfoGetter, TokenVerifier


def test_raise_error_invalid_set_scope():
    # scope_key is not declaired
    token_verifier = TokenVerifier(jwks=JWKS(keys=[]))
    try:
        raised = False
        token_verifier.scope("read:test")
    except AttributeError:
        raised = True
    assert raised, "raise AttributeError for invalid instanse attributes wrt scope"


def test_forget_def_user_info():
    try:
        error_check = False
        TokenUserInfoGetter()
    except AttributeError:
        error_check = True
    assert error_check, "user_info is Required to define pydantic model"
