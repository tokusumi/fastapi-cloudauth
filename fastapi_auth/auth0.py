from .base import Base


class Auth0(Base):
    def __init__(self, domain: str, *args, **kwargs):
        url = f"https://{domain}/.well-known/jwks.json"
        super().__init__(url, *args, **kwargs)
