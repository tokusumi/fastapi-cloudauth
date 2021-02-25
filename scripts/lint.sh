#!/usr/bin/env bash

set -e
set -x

mypy fastapi_cloudauth
flake8 fastapi_cloudauth tests
black fastapi_cloudauth tests --check
isort fastapi_cloudauth tests scripts --check-only