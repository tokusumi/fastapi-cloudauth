from fastapi_auth.base import TokenUserInfoGetter


def test_forget_def_user_info():
    try:
        error_check = False
        TokenUserInfoGetter()
    except AttributeError:
        error_check = True
    assert error_check, "user_info is Required to define pydantic model"
