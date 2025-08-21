#!/bin/bash

# =============================================================================
# Schema Version Check and Upgrade Script
# =============================================================================
# This script checks your database schema version and applies necessary upgrades

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}TLS Scanner Schema Version Check${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
    echo -e "${GREEN}✓ Loaded .env file${NC}"
else
    echo -e "${RED}✗ No .env file found${NC}"
    exit 1
fi

# Parse database URL
if [ -z "$DATABASE_URL" ]; then
    echo -e "${RED}✗ DATABASE_URL not set in .env${NC}"
    exit 1
fi

# Extract connection details
DB_USER=$(echo $DATABASE_URL | sed -n 's/.*:\/\/\([^:]*\):.*/\1/p')
DB_PASS=$(echo $DATABASE_URL | sed -n 's/.*:\/\/[^:]*:\([^@]*\)@.*/\1/p')
DB_HOST=$(echo $DATABASE_URL | sed -n 's/.*@\([^/]*\)\/.*/\1/p')
DB_NAME=$(echo $DATABASE_URL | sed -n 's/.*\/\([^?]*\).*/\1/p')

# Check if using Docker
if [ "$DB_HOST" = "postgres" ]; then
    USE_DOCKER=true
    echo -e "${BLUE}ℹ Using Docker container for database${NC}"
else
    USE_DOCKER=false
    echo -e "${BLUE}ℹ Using external database at $DB_HOST${NC}"
fi

# Function to run SQL command
run_sql() {
    local sql="$1"
    if [ "$USE_DOCKER" = true ]; then
        docker-compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" -t -c "$sql" 2>/dev/null | tr -d ' \n'
    else
        PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "$sql" 2>/dev/null | tr -d ' \n'
    fi
}

# Function to run SQL file
run_sql_file() {
    local file="$1"
    echo -e "${BLUE}  → Executing: $(basename $file)${NC}"
    if [ "$USE_DOCKER" = true ]; then
        docker-compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" < "$file"
    else
        PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" < "$file"
    fi
}

echo ""
echo -e "${YELLOW}Checking database connection...${NC}"

# Test connection
if run_sql "SELECT 1;" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Database connection successful${NC}"
else
    echo -e "${RED}✗ Cannot connect to database${NC}"
    echo "  Please ensure:"
    echo "  - Database is running (docker-compose up -d postgres)"
    echo "  - DATABASE_URL is correct in .env"
    exit 1
fi

echo ""
echo -e "${YELLOW}Checking schema version...${NC}"

# Check if any tables exist
TABLE_COUNT=$(run_sql "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';")

if [ "$TABLE_COUNT" = "0" ] || [ -z "$TABLE_COUNT" ]; then
    # Fresh installation
    echo -e "${CYAN}ℹ No tables found - this is a fresh installation${NC}"
    echo ""
    echo -e "${YELLOW}Installing schema v2.0.0...${NC}"
    
    if run_sql_file "scripts/schema-v2.sql"; then
        echo ""
        echo -e "${GREEN}✅ Schema v2.0.0 installed successfully!${NC}"
    else
        echo -e "${RED}✗ Failed to install schema${NC}"
        exit 1
    fi
else
    # Existing installation - check version
    VERSION=$(run_sql "SELECT version FROM schema_version WHERE id = 1;" 2>/dev/null || echo "")
    
    if [ -z "$VERSION" ]; then
        # No version table - must be v1
        echo -e "${YELLOW}⚠ No version tracking found - detected v1 schema${NC}"
        echo -e "${BLUE}  Current version: v1.x (original schema)${NC}"
        echo -e "${BLUE}  Target version: v2.0.0${NC}"
        echo ""
        
        read -p "$(echo -e ${YELLOW}Upgrade to v2.0.0? This will add auth tables. [y/N]: ${NC})" -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Upgrading schema to v2.0.0...${NC}"
            
            if run_sql_file "scripts/upgrade-v1-to-v2.sql"; then
                echo ""
                echo -e "${GREEN}✅ Successfully upgraded to v2.0.0!${NC}"
            else
                echo -e "${RED}✗ Upgrade failed${NC}"
                exit 1
            fi
        else
            echo -e "${YELLOW}ℹ Upgrade cancelled - remaining at v1${NC}"
        fi
    else
        echo -e "${GREEN}✓ Current schema version: $VERSION${NC}"
        
        if [ "$VERSION" = "2.0.0" ]; then
            echo -e "${GREEN}✓ Schema is up to date!${NC}"
        else
            echo -e "${YELLOW}ℹ Unknown version: $VERSION${NC}"
        fi
    fi
fi

# Display summary
echo ""
echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}Schema Check Complete${NC}"
echo -e "${CYAN}================================================${NC}"

# Get final version
FINAL_VERSION=$(run_sql "SELECT version FROM schema_version WHERE id = 1;" 2>/dev/null || echo "1.x")

echo ""
echo -e "${BLUE}Summary:${NC}"
echo -e "  Database: ${GREEN}$DB_NAME${NC} @ ${GREEN}$DB_HOST${NC}"
echo -e "  Schema Version: ${GREEN}$FINAL_VERSION${NC}"
echo -e "  Auth Mode: ${GREEN}${AUTH_MODE:-none}${NC}"

# Count tables
AUTH_TABLES=$(run_sql "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('users', 'refresh_tokens', 'audit_log', 'api_keys');")
CORE_TABLES=$(run_sql "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('scans', 'scan_queue', 'scan_vulnerabilities', 'scan_grade_degradations');")

echo -e "  Core Tables: ${GREEN}$CORE_TABLES/4${NC}"
echo -e "  Auth Tables: ${GREEN}$AUTH_TABLES/4${NC}"

if [ "$FINAL_VERSION" = "2.0.0" ]; then
    echo ""
    echo -e "${BLUE}Features Available:${NC}"
    echo -e "  ✓ Core scanning functionality"
    echo -e "  ✓ Authentication tables (active when AUTH_MODE != none)"
    echo -e "  ✓ Admin features (data retention, system config)"
    echo -e "  ✓ Audit logging"
    echo -e "  ✓ Schema version tracking"
fi

echo ""