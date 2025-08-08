#!/bin/bash

# TLS Scanner Portal - Database Cleanup Script
# Usage: ./cleanup-db.sh [7|30|90|ALL]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Find the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Load environment variables from .env file
if [ -f "$PROJECT_ROOT/.env" ]; then
    echo -e "${YELLOW}Loading configuration from .env file...${NC}"
    set -a
    source "$PROJECT_ROOT/.env"
    set +a
else
    echo -e "${RED}Error: .env file not found!${NC}"
    echo "Please create a .env file in the project root with your database configuration."
    echo "You can copy .env.example as a starting point:"
    echo "  cp $PROJECT_ROOT/.env.example $PROJECT_ROOT/.env"
    exit 1
fi

# Parse DATABASE_URL or use individual variables
if [ -n "$DATABASE_URL" ]; then
    # Parse postgres://user:pass@host:port/dbname?sslmode=disable
    # Remove the postgres:// prefix and any query parameters
    DB_URL="${DATABASE_URL#postgres://}"
    DB_URL="${DB_URL#postgresql://}"
    DB_URL="${DB_URL%%\?*}"
    
    # Extract components
    USER_PASS="${DB_URL%%@*}"
    HOST_PORT_DB="${DB_URL#*@}"
    
    DB_USER="${USER_PASS%%:*}"
    DB_PASS="${USER_PASS#*:}"
    
    HOST_PORT="${HOST_PORT_DB%%/*}"
    DB_NAME="${HOST_PORT_DB#*/}"
    
    if [[ "$HOST_PORT" == *":"* ]]; then
        DB_HOST="${HOST_PORT%%:*}"
        DB_PORT="${HOST_PORT#*:}"
    else
        DB_HOST="$HOST_PORT"
        DB_PORT="5432"
    fi
else
    # Use individual variables with defaults
    DB_HOST="${POSTGRES_HOST:-localhost}"
    DB_PORT="${POSTGRES_PORT:-5432}"
    DB_NAME="${POSTGRES_DB:-tlsscanner}"
    DB_USER="${POSTGRES_USER:-postgres}"
    DB_PASS="${POSTGRES_PASSWORD}"
fi

# Check if we have required credentials
if [ -z "$DB_PASS" ]; then
    echo -e "${RED}Error: Database password not found in .env file!${NC}"
    echo "Please ensure POSTGRES_PASSWORD or DATABASE_URL is set in your .env file."
    exit 1
fi

# Check if we're running inside Docker network
if [ -f /.dockerenv ] || [ -n "$DOCKER_CONTAINER" ]; then
    # If inside Docker, use the service name
    DB_HOST="postgres"
elif [[ "$DB_HOST" == "postgres" ]]; then
    # If outside Docker but host is "postgres", change to localhost
    DB_HOST="localhost"
fi

# Function to show usage
usage() {
    echo "Usage: $0 [7|30|90|ALL]"
    echo ""
    echo "Options:"
    echo "  7    - Delete scans older than 7 days"
    echo "  30   - Delete scans older than 30 days"
    echo "  90   - Delete scans older than 90 days"
    echo "  ALL  - Delete ALL scans (WARNING: This will clear all data!)"
    echo ""
    echo "Database configuration is loaded from: $PROJECT_ROOT/.env"
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

# Set PGPASSWORD for non-interactive psql
export PGPASSWORD="$DB_PASS"

# Function to execute SQL
execute_sql() {
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "$1"
}

# Function to get count
get_count() {
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "$1" | xargs
}

# Test database connection
echo -e "${YELLOW}Connecting to database at $DB_HOST:$DB_PORT/$DB_NAME...${NC}"
if ! execute_sql "SELECT 1" > /dev/null 2>&1; then
    echo -e "${RED}Error: Unable to connect to database!${NC}"
    echo "Please check your .env configuration and ensure the database is running."
    exit 1
fi

# Build the WHERE clause based on option
if [ "$OPTION" = "ALL" ]; then
    WHERE_CLAUSE=""
    DESCRIPTION="ALL scans"
else
    WHERE_CLAUSE="WHERE created_at < NOW() - INTERVAL '$OPTION days'"
    DESCRIPTION="scans older than $OPTION days"
fi

# Get counts before deletion
echo -e "${YELLOW}Checking database...${NC}"
SCAN_COUNT=$(get_count "SELECT COUNT(*) FROM scans $WHERE_CLAUSE")
QUEUE_COUNT=$(get_count "SELECT COUNT(*) FROM scan_queue $WHERE_CLAUSE")

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

# Delete from queue first (has foreign key to scans)
if [ "$QUEUE_COUNT" -gt 0 ]; then
    echo -n "Deleting queue entries... "
    execute_sql "DELETE FROM scan_queue $WHERE_CLAUSE" > /dev/null 2>&1
    echo -e "${GREEN}Done${NC}"
fi

# The related tables will be cleaned up automatically due to CASCADE
if [ "$SCAN_COUNT" -gt 0 ]; then
    echo -n "Deleting scans (and related data)... "
    execute_sql "DELETE FROM scans $WHERE_CLAUSE" > /dev/null 2>&1
    echo -e "${GREEN}Done${NC}"
fi

# Vacuum to reclaim space
echo -n "Optimizing database... "
execute_sql "VACUUM ANALYZE" > /dev/null 2>&1
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
REMAINING_SCANS=$(get_count "SELECT COUNT(*) FROM scans")
echo ""
echo "Remaining in database: $REMAINING_SCANS scans"