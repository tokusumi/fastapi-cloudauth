#!/usr/bin/env bash

set -e
set -x

bash ./scripts/lint.sh
pytest --cov=fastapi_cloudauth --cov=tests --cov-report=xml --disable-warnings tests/