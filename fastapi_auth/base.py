from typing import List, Dict, Optional, Any
import requests
from jose import jwk, jwt
from jose.utils import base64url_decode
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from starlette import status


class JWKS(BaseModel):
    keys: List[Dict[str, Any]]

    @classmethod
    def fromurl(cls, url: str):
        """
        get and parse json into jwks from endpoint as follows,
        https://xxx/.well-known/jwks.json
        """
        return cls.parse_obj(requests.get(url).json())


class Base:
    def __init__(self, url: str, auto_error=True, *args, **kwargs):
        jwks = JWKS.fromurl(url)
        self.jwks_to_key = {_jwk["kid"]: jwk.construct(_jwk) for _jwk in jwks.keys}
        self.auto_error = auto_error

    def get_publickey(self, http_auth: HTTPAuthorizationCredentials):
        token = http_auth.credentials
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            else:
                return None
        publickey = self.jwks_to_key.get(kid)
        if not publickey:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="JWK public key not found",
                )
            else:
                return None
        return publickey

    async def __call__(
        self, http_auth: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer())
    ) -> Optional[Dict[str, str]]:
        if not http_auth:
            # error handling is included in HTTPBearer
            return None

        public_key = self.get_publickey(http_auth)
        if not public_key:
            # error handling is included in self.get_publickey
            return None

        message, encoded_sig = http_auth.credentials.rsplit(".", 1)
        decoded_sig = base64url_decode(encoded_sig.encode())
        is_verified = public_key.verify(message.encode(), decoded_sig)
        if not is_verified:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Not verified"
                )
            else:
                return None
        claims = jwt.get_unverified_claims(http_auth.credentials)
        return claims
