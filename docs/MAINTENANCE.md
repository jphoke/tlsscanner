# Maintenance Guide

This guide covers routine maintenance tasks, database management, and troubleshooting for the TLS Scanner Portal.

## Table of Contents

- [Database Maintenance](#database-maintenance)
- [Log Management](#log-management)
- [Performance Optimization](#performance-optimization)
- [Backup and Recovery](#backup-and-recovery)
- [Security Updates](#security-updates)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

## Database Maintenance

### Scan Data Cleanup

The scanner stores all scan results in PostgreSQL. Over time, this data can grow significantly. Use the provided cleanup scripts to manage database size.

#### Using Make Commands

```bash
# Delete scans older than 7 days
make cleanup-7

# Delete scans older than 30 days
make cleanup-30

# Delete scans older than 90 days
make cleanup-90

# Delete ALL scans (requires confirmation)
make cleanup-all
```

#### Using Docker Script

```bash
# Run cleanup script with Docker
./scripts/docker-db-cleanup.sh [7|30|90|ALL]

# Examples:
./scripts/docker-db-cleanup.sh 30    # Delete scans older than 30 days
./scripts/docker-db-cleanup.sh ALL   # Delete all scans (with confirmation)
```

#### Manual Database Cleanup

```sql
-- Connect to database
docker exec -it tlsscanner-postgres psql -U tlsscanner

-- Check database size
SELECT pg_database_size('tlsscanner') / 1024 / 1024 as size_mb;

-- Count scans by age
SELECT 
    CASE 
        WHEN created_at > NOW() - INTERVAL '7 days' THEN 'Last 7 days'
        WHEN created_at > NOW() - INTERVAL '30 days' THEN '7-30 days'
        WHEN created_at > NOW() - INTERVAL '90 days' THEN '30-90 days'
        ELSE 'Older than 90 days'
    END as age_group,
    COUNT(*) as scan_count
FROM scans
GROUP BY age_group
ORDER BY MIN(created_at) DESC;

-- Delete old scans manually
DELETE FROM scans WHERE created_at < NOW() - INTERVAL '30 days';

-- Reclaim space
VACUUM FULL ANALYZE;
```

### Database Optimization

#### Regular Maintenance Tasks

```bash
# Run VACUUM to reclaim space
docker exec tlsscanner-postgres psql -U tlsscanner -c "VACUUM ANALYZE;"

# Reindex for better performance
docker exec tlsscanner-postgres psql -U tlsscanner -c "REINDEX DATABASE tlsscanner;"

# Update statistics
docker exec tlsscanner-postgres psql -U tlsscanner -c "ANALYZE;"
```

#### Automated Maintenance

Create a cron job for regular maintenance:

```bash
# Create maintenance script
cat > /opt/tlsscanner/maintenance.sh << 'EOF'
#!/bin/bash
# TLS Scanner maintenance script

# Cleanup old scans (older than 30 days)
cd /opt/tlsscanner
./scripts/docker-db-cleanup.sh 30

# Optimize database
docker exec tlsscanner-postgres psql -U tlsscanner -c "VACUUM ANALYZE;"

# Log rotation
find /var/log/tlsscanner -name "*.log" -mtime +7 -delete
EOF

chmod +x /opt/tlsscanner/maintenance.sh

# Add to crontab (runs daily at 2 AM)
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/tlsscanner/maintenance.sh") | crontab -
```

## Log Management

### Application Logs

```bash
# View API logs
docker logs tlsscanner-api -f

# View last 100 lines
docker logs tlsscanner-api --tail 100

# Save logs to file
docker logs tlsscanner-api > api-logs.txt 2>&1
```

### Log Rotation

Configure Docker log rotation in `/etc/docker/daemon.json`:

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

Restart Docker after changes:
```bash
sudo systemctl restart docker
```

### Structured Logging

For production, configure structured logging:

```go
// In cmd/api/main.go
import "github.com/sirupsen/logrus"

log := logrus.New()
log.SetFormatter(&logrus.JSONFormatter{})
log.WithFields(logrus.Fields{
    "target": target,
    "grade": result.Grade,
    "duration": duration,
}).Info("Scan completed")
```

## Performance Optimization

### Database Performance

#### Indexes

Ensure proper indexes exist:

```sql
-- Check existing indexes
SELECT indexname, indexdef 
FROM pg_indexes 
WHERE tablename = 'scans';

-- Add missing indexes if needed
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_grade ON scans(grade);
```

#### Connection Pooling

Configure connection pool settings:

```go
// In pkg/database/postgres.go
db.SetMaxOpenConns(25)
db.SetMaxIdleConns(5)
db.SetConnMaxLifetime(5 * time.Minute)
```

### Redis Performance

#### Memory Management

```bash
# Check Redis memory usage
docker exec tlsscanner-redis redis-cli INFO memory

# Set memory limit
docker exec tlsscanner-redis redis-cli CONFIG SET maxmemory 512mb
docker exec tlsscanner-redis redis-cli CONFIG SET maxmemory-policy allkeys-lru

# Clear cache if needed
docker exec tlsscanner-redis redis-cli FLUSHDB
```

#### Persistence Settings

For better performance, adjust persistence:

```bash
# Disable AOF for better performance (less durability)
docker exec tlsscanner-redis redis-cli CONFIG SET appendonly no

# Or adjust fsync frequency
docker exec tlsscanner-redis redis-cli CONFIG SET appendfsync everysec
```

### Scanner Performance

#### Worker Pool Tuning

Adjust based on server resources:

```bash
# Set via environment variable
export MAX_CONCURRENT_SCANS=20

# Or in docker-compose.yml
environment:
  - MAX_CONCURRENT_SCANS=20
```

#### Timeout Settings

```bash
# Adjust scan timeout (seconds)
export SCAN_TIMEOUT=60

# Connection timeout
export CONNECT_TIMEOUT=10
```

## Backup and Recovery

### Automated Backups

#### Database Backup Script

```bash
#!/bin/bash
# /opt/tlsscanner/backup.sh

BACKUP_DIR="/backups/tlsscanner"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
echo "Starting database backup..."
docker exec tlsscanner-postgres pg_dump -U tlsscanner tlsscanner | gzip > $BACKUP_DIR/tlsscanner_db_$DATE.sql.gz

# Backup configuration files
echo "Backing up configuration..."
tar -czf $BACKUP_DIR/tlsscanner_config_$DATE.tar.gz .env docker-compose.yml configs/

# Remove old backups
echo "Cleaning old backups..."
find $BACKUP_DIR -name "tlsscanner_*.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_DIR/tlsscanner_db_$DATE.sql.gz"
```

#### Schedule Backups

```bash
# Add to crontab (daily at 3 AM)
0 3 * * * /opt/tlsscanner/backup.sh >> /var/log/tlsscanner-backup.log 2>&1
```

### Recovery Procedures

#### Database Recovery

```bash
# Stop the API to prevent new writes
docker stop tlsscanner-api

# Restore from backup
gunzip < /backups/tlsscanner_db_20240101_030000.sql.gz | \
  docker exec -i tlsscanner-postgres psql -U tlsscanner tlsscanner

# Restart services
docker start tlsscanner-api
```

#### Full System Recovery

```bash
# Restore configuration
cd /opt/tlsscanner
tar -xzf /backups/tlsscanner_config_20240101_030000.tar.gz

# Restore database
gunzip < /backups/tlsscanner_db_20240101_030000.sql.gz | \
  docker exec -i tlsscanner-postgres psql -U tlsscanner tlsscanner

# Rebuild and restart
docker compose down
docker compose up -d --build
```

## Security Updates

### System Updates

```bash
# Update host system
sudo apt update && sudo apt upgrade -y

# Update Docker images
docker compose pull
docker compose up -d
```

### Dependency Updates

```bash
# Update Go dependencies
go get -u ./...
go mod tidy

# Check for vulnerabilities
go list -json -m all | nancy sleuth

# Update npm dependencies (if any)
npm audit fix
```

### Container Security

```bash
# Scan images for vulnerabilities
docker scout cves tlsscanner-api:latest

# Or use Trivy
trivy image tlsscanner-api:latest
```

## Monitoring

### Health Checks

#### API Health

```bash
# Basic health check
curl http://localhost:${API_HOST_PORT:-8000}/api/v1/health

# Detailed health with dependencies
curl http://localhost:${API_HOST_PORT:-8000}/api/v1/health/ready
```

#### Automated Health Monitoring

```bash
#!/bin/bash
# /opt/tlsscanner/health-check.sh

API_URL="http://localhost:${API_HOST_PORT:-8000}/api/v1/health"
ALERT_EMAIL="admin@example.com"

if ! curl -f -s $API_URL > /dev/null; then
    echo "TLS Scanner API is DOWN" | mail -s "TLS Scanner Alert" $ALERT_EMAIL
    
    # Attempt restart
    docker restart tlsscanner-api
fi
```

Add to crontab (every 5 minutes):
```bash
*/5 * * * * /opt/tlsscanner/health-check.sh
```

### Resource Monitoring

```bash
# Real-time container stats
docker stats

# Check disk usage
df -h
du -sh /var/lib/docker/volumes/tlsscanner_postgres_data

# Memory usage
free -h

# Database connections
docker exec tlsscanner-postgres psql -U tlsscanner -c \
  "SELECT count(*) FROM pg_stat_activity WHERE datname = 'tlsscanner';"
```

### Performance Metrics

```sql
-- Slow queries
SELECT query, mean_exec_time, calls 
FROM pg_stat_statements 
WHERE mean_exec_time > 100 
ORDER BY mean_exec_time DESC 
LIMIT 10;

-- Table sizes
SELECT 
    schemaname AS table_schema,
    tablename AS table_name,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

## Troubleshooting

### Common Issues

#### High Database CPU Usage

```bash
# Check running queries
docker exec tlsscanner-postgres psql -U tlsscanner -c \
  "SELECT pid, now() - pg_stat_activity.query_start AS duration, query 
   FROM pg_stat_activity 
   WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';"

# Kill long-running query
docker exec tlsscanner-postgres psql -U tlsscanner -c \
  "SELECT pg_terminate_backend(PID);"
```

#### Redis Memory Issues

```bash
# Check memory usage
docker exec tlsscanner-redis redis-cli INFO memory | grep used_memory_human

# Clear expired keys
docker exec tlsscanner-redis redis-cli --scan --pattern "*" | \
  xargs -L 1 docker exec tlsscanner-redis redis-cli TTL | \
  grep -v "^-1$" | wc -l
```

#### Disk Space Issues

```bash
# Find large files
find /var/lib/docker -type f -size +100M -exec ls -lh {} \;

# Clean Docker resources
docker system prune -a -f --volumes

# Clean old logs
find /var/log -name "*.log" -mtime +30 -delete
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Set debug mode
docker exec tlsscanner-api sh -c 'export GIN_MODE=debug'

# Or in docker-compose.yml
environment:
  - GIN_MODE=debug
  - LOG_LEVEL=debug
```

### Emergency Procedures

#### Service Won't Start

```bash
# Check logs
docker compose logs

# Reset everything (WARNING: Data loss)
docker compose down -v
docker compose up -d --build

# Restore from backup
./restore-from-backup.sh
```

#### Database Corruption

```bash
# Stop services
docker compose stop

# Backup corrupted database (just in case)
docker exec tlsscanner-postgres pg_dump -U tlsscanner tlsscanner > corrupted-backup.sql

# Recreate database
docker compose down
docker volume rm tlsscanner_postgres_data
docker compose up -d

# Restore from last good backup
gunzip < last-good-backup.sql.gz | docker exec -i tlsscanner-postgres psql -U tlsscanner
```

## Maintenance Calendar

### Daily Tasks
- Check health endpoints
- Monitor disk space
- Review error logs

### Weekly Tasks
- Database VACUUM ANALYZE
- Review scan statistics
- Check backup integrity

### Monthly Tasks
- Clean old scans (30+ days)
- Update dependencies
- Security scan containers
- Review performance metrics

### Quarterly Tasks
- Full system backup test
- Disaster recovery drill
- Performance tuning review
- Security audit