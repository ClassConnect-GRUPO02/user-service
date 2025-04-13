#!/bin/bash

set -e

docker compose \
    -f docker-compose-test.yaml up \
    --abort-on-container-exit -V
