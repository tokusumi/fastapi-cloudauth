from pydantic import BaseModel, Field
from .base import TokenUserInfoGetter, JWKS


class FirebaseClaims(BaseModel):
    user_id: str = Field(alias="user_id")
    email: str = Field(None, alias="email")


class FirebaseCurrentUser(TokenUserInfoGetter):
    """
    Verify ID token and get user info of Firebase
    """

    user_info = FirebaseClaims

    def __init__(self, *args, **kwargs):
        url = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
        jwks = JWKS.firebase(url)
        super().__init__(jwks, *args, **kwargs)
