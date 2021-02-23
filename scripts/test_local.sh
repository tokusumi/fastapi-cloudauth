#!/usr/bin/env bash

source ./scripts/load_env.sh
bash ./scripts/lint.sh
pytest --cov=fastapi_cloudauth --cov=tests --cov-report=term-missing tests ${@}
