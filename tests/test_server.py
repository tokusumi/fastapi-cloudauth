import os
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_auth import Auth0 as Auth

app = FastAPI()

auth = Auth(domain=os.environ["domain"])


@app.get("/", dependencies=[Depends(auth)])
async def secure(payload=Depends(auth)) -> bool:
    return payload


client = TestClient(app)


def test_read_main():
    response = client.get(
        "/", headers={"authorization": f"Bearer {os.environ['token']}"}
    )
    assert response.status_code == 200
