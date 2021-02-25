import os
from pydantic import BaseModel
from fastapi import FastAPI, Depends
from fastapi_cloudauth.cognito import Cognito, CognitoCurrentUser, CognitoClaims

tags_metadata = [
    {
        "name": "Cognito",
        "description": "Operations with access/ID token, provided by AWS Cognito.",
    }
]

app = FastAPI(
    title="FastAPI CloudAuth Project",
    description="Simple integration between FastAPI and cloud authentication services (AWS Cognito, Auth0, Firebase Authentication).",
    openapi_tags=tags_metadata,
)

auth = Cognito(
    region=os.environ["COGNITO_REGION"], userPoolId=os.environ["COGNITO_USERPOOLID"]
)


@app.get("/", dependencies=[Depends(auth.scope("read:users"))], tags=["Cognito"])
def secure():
    # access token is valid
    return "Hello"


class AccessUser(BaseModel):
    sub: str


@app.get("/access/", tags=["Cognito"])
def secure_access(current_user: AccessUser = Depends(auth.claim(AccessUser))):
    # access token is valid and getting user info from access token
    return f"Hello", {current_user.sub}


get_current_user = CognitoCurrentUser(
    region=os.environ["COGNITO_REGION"], userPoolId=os.environ["COGNITO_USERPOOLID"]
)


@app.get("/user/", tags=["Cognito"])
def secure_user(current_user: CognitoClaims = Depends(get_current_user)):
    # ID token is valid and getting user info from ID token
    return f"Hello, {current_user.username}"
