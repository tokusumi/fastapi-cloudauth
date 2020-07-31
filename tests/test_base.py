import os
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_auth.base import TokenUserInfoGetter
from fastapi_auth import Auth0 as Auth

app = FastAPI()

auth = Auth(domain=os.environ["DOMAIN"])
auth_no_error = Auth(domain=os.environ["DOMAIN"], auto_error=False)


@app.get("/", dependencies=[Depends(auth)])
async def secure(payload=Depends(auth)) -> bool:
    return payload


@app.get("/no-error/", dependencies=[Depends(auth_no_error)])
async def secure_no_error(payload=Depends(auth_no_error)) -> bool:
    return payload


client = TestClient(app)


def test_valid_token():
    response = client.get(
        "/", headers={"authorization": f"Bearer {os.environ['TOKEN']}"}
    )
    assert response.status_code == 200


def test_no_token():
    # handle in fastapi.security.HtTPBearer
    response = client.get("/")
    assert response.status_code == 403


def test_incompatible_kid_token():
    # manipulate header
    token = os.environ["TOKEN"].split(".", 1)[-1]
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIzMDQ5ODE1MWMyMTRiNzg4ZGQ5N2YyMmI4NTQxMGE1In0."
        + token
    )
    response = client.get("/", headers={"authorization": f"Bearer {token}"})
    assert response.status_code == 403, "must not be verified"

    # not auto_error
    response = client.get("/no-error/", headers={"authorization": f"Bearer {token}"},)
    assert response.status_code == 200, "must not be verified"
    assert response.content == b"null"


def test_no_kid_token():
    # manipulate header
    token = os.environ["TOKEN"].split(".", 1)[-1]
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + token
    response = client.get("/", headers={"authorization": f"Bearer {token}"})
    assert response.status_code == 403, "must not be verified"

    # not auto_error
    response = client.get("/no-error/", headers={"authorization": f"Bearer {token}"},)
    assert response.status_code == 200, "must not be verified"
    assert response.content == b"null"


def test_not_verified_token():
    # manipulate public_key
    response = client.get(
        "/", headers={"authorization": f"Bearer {os.environ['TOKEN']}"[:-3] + "aaa"}
    )
    assert response.status_code == 403, "must not be verified"

    # not auto_error
    response = client.get(
        "/no-error/",
        headers={"authorization": f"Bearer {os.environ['TOKEN']}"[:-3] + "aaa"},
    )
    assert response.status_code == 200, "must not be verified"
    assert response.content == b"null"


def test_forget_def_user_info():
    try:
        error_check = False
        TokenUserInfoGetter()
    except AttributeError:
        error_check = True
    assert error_check, "user_info is Required to define pydantic model"
