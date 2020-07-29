#!/usr/bin/env bash

set -e

source ./scripts/load_env.sh
pytest --cov=fastapi_auth --cov=tests --cov-report=term-missing tests ${@}