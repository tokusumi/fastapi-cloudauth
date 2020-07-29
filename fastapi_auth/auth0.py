from .base import Base, JWKS


class Auth0(Base):
    def __init__(self, domain: str, *args, **kwargs):
        url = f"https://{domain}/.well-known/jwks.json"
        jwks = JWKS.fromurl(url)
        super().__init__(jwks, *args, **kwargs)
