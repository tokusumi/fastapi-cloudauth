from fastapi import FastAPI, Depends
from fastapi_cloudauth.firebase import FirebaseCurrentUser, FirebaseClaims

tags_metadata = [
    {
        "name": "Firebase",
        "description": "Operations with access/ID token, provided by Firebase Authentication.",
    }
]

app = FastAPI(
    title="FastAPI CloudAuth Project",
    description="Simple integration between FastAPI and cloud authentication services (AWS Cognito, Auth0, Firebase Authentication).",
    openapi_tags=tags_metadata,
)

get_current_user = FirebaseCurrentUser()


@app.get("/user/", tags=["Firebase"])
def secure_user(current_user: FirebaseClaims = Depends(get_current_user)):
    # ID token is valid and getting user info from ID token
    return f"Hello, {current_user.user_id}"
