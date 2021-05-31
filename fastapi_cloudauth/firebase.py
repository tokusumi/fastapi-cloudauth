from calendar import timegm
from datetime import datetime
from typing import Any, Dict

from fastapi import HTTPException
from pydantic import BaseModel, Field
from starlette import status

from .base import UserInfoAuth
from .messages import NOT_VERIFIED
from .verification import JWKS, ExtraVerifier


class FirebaseClaims(BaseModel):
    user_id: str = Field(alias="user_id")
    email: str = Field(None, alias="email")


class FirebaseCurrentUser(UserInfoAuth):
    """
    Verify ID token and get user info of Firebase
    """

    user_info = FirebaseClaims

    def __init__(self, project_id: str, *args: Any, **kwargs: Any):
        url = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
        jwks = JWKS.firebase(url)

        super().__init__(
            jwks,
            *args,
            user_info=self.user_info,
            audience=project_id,
            issuer=f"https://securetoken.google.com/{project_id}",
            extra=FirebaseExtraVerifier(project_id=project_id),
            **kwargs,
        )


class FirebaseExtraVerifier(ExtraVerifier):
    def __init__(self, project_id: str):
        self._pjt_id = project_id

    def __call__(self, claims: Dict[str, str], auto_error: bool = True) -> bool:
        # auth_time must be past time
        if claims.get("auth_time"):
            auth_time = int(claims["auth_time"])
            now = timegm(datetime.utcnow().utctimetuple())
            if now < auth_time:
                if auto_error:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED, detail=NOT_VERIFIED
                    )
                return False
        return True
