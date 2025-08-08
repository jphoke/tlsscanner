#!/bin/bash

# Docker wrapper for cleanup-db.sh
# This script runs the cleanup inside the postgres container

# Check arguments
if [ $# -ne 1 ]; then
    echo "Usage: $0 [7|30|90|ALL]"
    exit 1
fi

# Run cleanup script inside the API container which has access to .env
docker compose exec -T api sh -c "
    apk add --no-cache postgresql-client >/dev/null 2>&1
    cd /app
    if [ ! -f scripts/cleanup-db.sh ]; then
        echo 'Error: cleanup script not found in container'
        exit 1
    fi
    DOCKER_CONTAINER=1 scripts/cleanup-db.sh $1
"