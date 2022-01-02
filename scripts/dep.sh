#!/usr/bin/env bash
# check dependency problem via install fastapi-cloudauth with wheel
set -e

poetry build
python3 -m venv env
source env/bin/activate
python3 -m pip install -U pip
python3 -m pip install wheel dist/fastapi_cloudauth-*.whl

# if not installed cryptography with python-jose, this line fails
python3 -c 'from fastapi_cloudauth.firebase import *; print(JWKS(url="https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"))'
echo "Success"