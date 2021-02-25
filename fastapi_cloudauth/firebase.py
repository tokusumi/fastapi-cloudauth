from typing import Any

from pydantic import BaseModel, Field

from .base import UserInfoAuth
from .verification import JWKS


class FirebaseClaims(BaseModel):
    user_id: str = Field(alias="user_id")
    email: str = Field(None, alias="email")


class FirebaseCurrentUser(UserInfoAuth):
    """
    Verify ID token and get user info of Firebase
    """

    user_info = FirebaseClaims

    def __init__(self, *args: Any, **kwargs: Any):
        url = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
        jwks = JWKS.firebase(url)
        super().__init__(jwks, *args, user_info=self.user_info, **kwargs)
