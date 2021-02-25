import os
from pydantic import BaseModel
from fastapi import FastAPI, Depends
from fastapi_cloudauth.auth0 import Auth0, Auth0CurrentUser, Auth0Claims

tags_metadata = [
    {
        "name": "Auth0",
        "description": "Operations with access/ID token, provided by Auth0.",
    }
]

app = FastAPI(
    title="FastAPI CloudAuth Project",
    description="Simple integration between FastAPI and cloud authentication services (AWS Cognito, Auth0, Firebase Authentication).",
    openapi_tags=tags_metadata,
)

auth = Auth0(domain=os.environ["AUTH0_DOMAIN"])


@app.get("/", dependencies=[Depends(auth.scope("read:users"))], tags=["Auth0"])
def secure():
    # access token is valid
    return "Hello"


class AccessUser(BaseModel):
    sub: str


@app.get("/access/", tags=["Auth0"])
def secure_access(current_user: AccessUser = Depends(auth.claim(AccessUser))):
    # access token is valid and getting user info from access token
    return f"Hello", {current_user.sub}


get_current_user = Auth0CurrentUser(domain=os.environ["AUTH0_DOMAIN"])


@app.get("/user/", tags=["Auth0"])
def secure_user(current_user: Auth0Claims = Depends(get_current_user)):
    # ID token is valid and getting user info from ID token
    return f"Hello, {current_user.username}"
