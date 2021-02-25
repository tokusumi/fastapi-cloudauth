#!/bin/sh -e
set -x

autoflake --remove-all-unused-imports --recursive --remove-unused-variables --in-place fastapi_cloudauth tests scripts --exclude=__init__.py
black fastapi_cloudauth tests scripts
isort fastapi_cloudauth tests scripts