#!/usr/bin/env bash

set -e

bash ./scripts/lint.sh
pytest --cov=fastapi_cloudauth --cov=tests --cov-report=xml --disable-warnings tests/