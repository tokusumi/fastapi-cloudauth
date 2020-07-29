#!/usr/bin/env bash

set -e
set -x

pytest --cov=fastapi_auth --cov=tests --cov-report=term-missing tests ${@}