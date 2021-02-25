#!/usr/bin/env bash

source ./scripts/load_env.sh
uvicorn docs.server.auth0:app
uvicorn docs.server.cognito:app
uvicorn docs.server.firebase:app