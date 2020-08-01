#!/usr/bin/env bash

set -e

source ./scripts/load_env.sh
pytest --cov=fastapi_cloudauth --cov=tests --cov-report=term-missing tests ${@}