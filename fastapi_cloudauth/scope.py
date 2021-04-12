import pydantic
from typing import List

VALID_COMPERATOR = ["any", "all"]


class AdvancedScope(pydantic.BaseModel):
    comperator: str
    scopes: List[str]

    @pydantic.validator("comperator")
    def valid_coperator(cls, value):
        if value not in VALID_COMPERATOR:
            raise ValueError("Coperator mus be one of '{VALID_COMPERATOR}'")
        return value
