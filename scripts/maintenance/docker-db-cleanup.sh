#!/bin/bash

# TLS Scanner Portal - Docker Database Cleanup Script
# This runs the cleanup through Docker containers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to show usage
usage() {
    echo "Usage: $0 [7|30|90|ALL]"
    echo ""
    echo "Options:"
    echo "  7    - Delete scans older than 7 days"
    echo "  30   - Delete scans older than 30 days"
    echo "  90   - Delete scans older than 90 days"
    echo "  ALL  - Delete ALL scans (WARNING: This will clear all data!)"
    exit 1
}

# Check arguments
if [ $# -ne 1 ]; then
    usage
fi

OPTION=$1

# Validate option
case $OPTION in
    7|30|90|ALL)
        ;;
    *)
        echo -e "${RED}Error: Invalid option '$OPTION'${NC}"
        usage
        ;;
esac

# Check if docker compose is running
if ! docker compose ps --format "{{.Name}}" | grep -q "tlsscanner-portal-postgres"; then
    echo -e "${RED}Error: PostgreSQL container is not running!${NC}"
    echo "Please start the services with: docker compose up -d"
    exit 1
fi

# Build the WHERE clause based on option
if [ "$OPTION" = "ALL" ]; then
    WHERE_CLAUSE=""
    COUNT_WHERE=""
    DESCRIPTION="ALL scans"
else
    WHERE_CLAUSE="WHERE created_at < NOW() - INTERVAL '$OPTION days'"
    COUNT_WHERE="WHERE created_at < NOW() - INTERVAL '$OPTION days'"
    DESCRIPTION="scans older than $OPTION days"
fi

# Get counts before deletion
echo -e "${YELLOW}Checking database...${NC}"
SCAN_COUNT=$(docker compose exec -T postgres psql -U postgres -d tlsscanner -t -c "SELECT COUNT(*) FROM scans $COUNT_WHERE" | xargs)
QUEUE_COUNT=$(docker compose exec -T postgres psql -U postgres -d tlsscanner -t -c "SELECT COUNT(*) FROM scan_queue $COUNT_WHERE" | xargs)

echo ""
echo -e "${YELLOW}Found:${NC}"
echo "  - $SCAN_COUNT scans to delete"
echo "  - $QUEUE_COUNT queue entries to delete"
echo ""

# Confirm deletion
if [ "$SCAN_COUNT" -eq 0 ] && [ "$QUEUE_COUNT" -eq 0 ]; then
    echo -e "${GREEN}No data to clean up.${NC}"
    exit 0
fi

echo -e "${RED}WARNING: This will permanently delete $DESCRIPTION!${NC}"
echo -n "Are you sure you want to continue? (yes/no): "
read -r CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Cleanup cancelled."
    exit 0
fi

# Perform cleanup
echo ""
echo -e "${YELLOW}Starting cleanup...${NC}"

if [ "$OPTION" = "ALL" ]; then
    # Use TRUNCATE for ALL option (faster and resets sequences)
    echo -n "Deleting all data... "
    docker compose exec -T postgres psql -U postgres -d tlsscanner -c "TRUNCATE scan_queue, scans CASCADE;" > /dev/null 2>&1
    echo -e "${GREEN}Done${NC}"
else
    # Delete from queue first (has foreign key to scans)
    if [ "$QUEUE_COUNT" -gt 0 ]; then
        echo -n "Deleting queue entries... "
        docker compose exec -T postgres psql -U postgres -d tlsscanner -c "DELETE FROM scan_queue $WHERE_CLAUSE;" > /dev/null 2>&1
        echo -e "${GREEN}Done${NC}"
    fi

    # Delete scans (related tables will be cleaned up automatically due to CASCADE)
    if [ "$SCAN_COUNT" -gt 0 ]; then
        echo -n "Deleting scans (and related data)... "
        docker compose exec -T postgres psql -U postgres -d tlsscanner -c "DELETE FROM scans $WHERE_CLAUSE;" > /dev/null 2>&1
        echo -e "${GREEN}Done${NC}"
    fi
fi

# Vacuum to reclaim space
echo -n "Optimizing database... "
docker compose exec -T postgres psql -U postgres -d tlsscanner -c "VACUUM ANALYZE;" > /dev/null 2>&1
echo -e "${GREEN}Done${NC}"

# Show results
echo ""
echo -e "${GREEN}Cleanup completed successfully!${NC}"
echo ""
echo "Deleted:"
echo "  - $SCAN_COUNT scans"
echo "  - $QUEUE_COUNT queue entries"
echo "  - All related data (vulnerabilities, grade degradations, weak protocols/ciphers)"

# Show remaining data
REMAINING_SCANS=$(docker compose exec -T postgres psql -U postgres -d tlsscanner -t -c "SELECT COUNT(*) FROM scans" | xargs)
echo ""
echo "Remaining in database: $REMAINING_SCANS scans"