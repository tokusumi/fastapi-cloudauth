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
    firebase_keys_url = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

    def __init__(self, project_id: str, *args: Any, **kwargs: Any):
        self._key_refresh_locked = False
        jwks = JWKS.firebase(self.firebase_keys_url)

        super().__init__(
            jwks,
            *args,
            user_info=self.user_info,
            audience=project_id,
            issuer=f"https://securetoken.google.com/{project_id}",
            extra=FirebaseExtraVerifier(project_id=project_id),
            **kwargs,
        )

    async def refresh_keys(self) -> None:
        if not self._key_refresh_locked:
            # Ensure only one key refresh can happen at once.
            # This prevents a dogpile of requests the second the keys expire
            # from causing a bunch of refreshes (each one is an http request).
            self._key_refresh_locked = True

            # Re-query the keys from firebase.
            # NOTE: The expires comes from an http header which is supposed to
            # be set to a time long before the keys are no longer in use.
            # This allows gradual roll-out of the keys and should prevent any
            # request from failing.
            # The only scenario which will result in failing requests is if
            # there are zero requests for the entire duration of the roll-out
            # (observed to be around 1 week), followed by a burst of multiple
            # requests at once.
            jwks = JWKS.firebase(self.firebase_keys_url)

            # Reset the keys and the expiry date.
            self._verifier._jwks_to_key = jwks.keys
            self._keys_expire = jwks.expires

            # Remove the lock.
            self._key_refresh_locked = False


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
