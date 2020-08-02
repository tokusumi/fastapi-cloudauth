#!/usr/bin/env bash

set -e

pytest --cov=fastapi_cloudauth --cov=tests --cov-report=xml --disable-warnings tests/