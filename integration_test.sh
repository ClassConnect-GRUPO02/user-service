#!/bin/bash

source .env
set -e

CONTAINER_ID=$(docker run --rm -d \
    -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
    -e PGUSER=${PGUSER} \
    -e PGPORT=${PGPORT} \
    -p ${PGPORT}:${PGPORT} \
    -v ./init.sql:/docker-entrypoint-initdb.d/init.sql \
    postgres:latest)

go test -race -coverprofile=coverage.out -covermode=atomic

docker stop $CONTAINER_ID
