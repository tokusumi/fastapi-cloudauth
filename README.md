# FastAPI Cloud Auth

![Tests](https://github.com/tokusumi/fastapi-cloudauth/workflows/Tests/badge.svg)
[![codecov](https://codecov.io/gh/tokusumi/fastapi-cloudauth/branch/master/graph/badge.svg)](https://codecov.io/gh/tokusumi/fastapi-cloudauth)
[![PyPI version](https://badge.fury.io/py/fastapi-cloudauth.svg)](https://badge.fury.io/py/fastapi-cloudauth)

fastapi-cloudauth supports simple integration between FastAPI and cloud authentication services (AWS Cognito, Auth0, Firebase Authentication). This standardize the interface for some authentication services.

## Features

* [X] Verify access/id token
* [X] Authenticate permission based on scope (or groups) within access token 
* [X] Get login user info (name, email, etc.) within ID token
* [X] Dependency injection for verification/getting user, powered by [FastAPI](https://github.com/tiangolo/fastapi)
* [X] Support for:
    * [X] [AWS Cognito](https://aws.amazon.com/jp/cognito/)
    * [X] [Auth0](https://auth0.com/jp/)
    * [x] [Firebase Auth](https://firebase.google.com/docs/auth) (Only ID token)

## Requirements

Python 3.6+

## Install

```console
$ pip install fastapi-cloudauth
```

## Example (AWS Cognito)

### Pre-requirement

* Check `region` and `userPoolID` of AWS Cognito that you manage to
* Create a user assigned `read:users` permission in AWS Cognito 
* Get Access/ID token for the created user

NOTE: access token is valid for verification and scope-based authentication. ID token is valid for verification and getting user info from claims.

### Create it

Create a file main.py with:

```python3
import os
from fastapi import FastAPI, Depends
from fastapi_cloudauth.cognito import Cognito, CognitoCurrentUser, CognitoClaims

app = FastAPI()
auth = Cognito(region=os.environ["REGION"], userPoolId=os.environ["USERPOOLID"])


@app.get("/", dependencies=[Depends(auth.scope("read:users"))])
def secure():
    # access token is valid
    return "Hello"


get_current_user = CognitoCurrentUser(
    region=os.environ["REGION"], userPoolId=os.environ["USERPOOLID"]
)


@app.get("/user/")
def secure_user(current_user: CognitoClaims = Depends(get_current_user)):
    # ID token is valid
    return f"Hello, {current_user.username}"
```

Run the server with:

```console
$ uvicorn main:app

INFO:     Started server process [15332]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

### Interactive API Doc

Go to http://127.0.0.1:8000/docs.

You will see the automatic interactive API documentation (provided by Swagger UI).

`Authorize` :unlock: button can be available at the endpoints injected dependency.

You can put token and try endpoint interactively.

![Swagger UI](https://raw.githubusercontent.com/tokusumi/fastapi-cloudauth/master/docs/src/authorize_in_doc.jpg)


## Example (Auth0)

### Pre-requirement

* Check `domain` of Auth0 that you manage to
* Create a user assigned `read:users` permission in Auth0 
* Get Access/ID token for the created user

### Create it

Create a file main.py with:

```python3
import os
from fastapi import FastAPI, Depends
from fastapi_cloudauth.auth0 import Auth0, Auth0CurrentUser, Auth0Claims

app = FastAPI()

auth = Auth0(domain=os.environ["DOMAIN"])


@app.get("/", dependencies=[Depends(auth.scope("read:users"))])
def secure():
    # access token is valid
    return "Hello"


get_current_user = Auth0CurrentUser(domain=os.environ["DOMAIN"])


@app.get("/user/")
def secure_user(current_user: CognitoClaims = Depends(get_current_user)):
    # ID token is valid
    return f"Hello, {current_user.username}"
```

Try to run the server and see interactive UI in the same way.


## Example (Firebase Authentication)

### Pre-requirement

* Create a user in Firebase Authentication 
* Get ID token for the created user

### Create it

Create a file main.py with:

```python3
from fastapi import FastAPI, Depends
from fastapi_cloudauth.firebase import FirebaseCurrentUser, FirebaseClaims

app = FastAPI()

get_current_user = FirebaseCurrentUser()


@app.get("/user/")
def secure_user(current_user: FirebaseClaims = Depends(get_current_user)):
    # ID token is valid
    return f"Hello, {current_user.user_id}"
```

Try to run the server and see interactive UI in the same way.

## Custom claims

We can get values for current user by writing a few lines.
For Auth0, ID token contains extra values as follows (Ref at [Auth0 official doc](https://auth0.com/docs/tokens)):

```json
{
  "iss": "http://YOUR_DOMAIN/",
  "sub": "auth0|123456",
  "aud": "YOUR_CLIENT_ID",
  "exp": 1311281970,
  "iat": 1311280970,
  "name": "Jane Doe",
  "given_name": "Jane",
  "family_name": "Doe",
  "gender": "female",
  "birthdate": "0000-10-31",
  "email": "janedoe@example.com",
  "picture": "http://example.com/janedoe/me.jpg"
}
```

By default, `Auth0CurrentUser` gives `pydantic.BaseModel` object, which has `username` (name) and `email` fields.

Here is a sample code to extract extra user information (adding `user_id`):

```python3
from pydantic import Field
from fastapi_cloudauth.auth0 import Auth0Claims  # base current user info model (inheriting `pydantic`).

# extend current user info model by `pydantic`.
class CustomAuth0Claims(Auth0Claims):
    user_id: str = Field(alias="sub")

get_current_user = Auth0CurrentUser(domain=DOMAIN)
get_current_user.user_info = CustomAuth0Claims  # override user info model by custom one.
```
