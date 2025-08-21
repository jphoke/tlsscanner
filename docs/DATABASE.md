# Database Management

Complete guide for TLS Scanner database setup, versioning, and migrations.

## Quick Commands

```bash
# Check your current version and upgrade if needed
./scripts/check-schema-version.sh

# Fresh installation (new deployments)
docker-compose exec -T postgres psql -U postgres -d tlsscanner < scripts/schema-v2.sql

# Upgrade from v1.x to v2.0.0
docker-compose exec -T postgres psql -U postgres -d tlsscanner < scripts/upgrade-v1-to-v2.sql

# Backup database
docker-compose exec postgres pg_dump -U postgres tlsscanner > backup_$(date +%Y%m%d_%H%M%S).sql
```

## Schema Versioning System

### Current Version: 2.0.0

The TLS Scanner uses a versioned schema system to ensure smooth upgrades and consistent deployments.

### Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2025-07 | Original schema (core tables only) |
| 2.0.0 | 2025-08 | Added authentication, admin features, version tracking |

### Design Philosophy

1. **Complete schema always installed** - All tables created upfront, including auth tables
2. **Unused tables don't hurt** - Auth tables exist but ignored when AUTH_MODE=none
3. **Version tracking** - `schema_version` table tracks current version
4. **Safe upgrades** - All scripts use `IF NOT EXISTS` and can be run multiple times

## Database Structure

### Core Tables (Always Used)
- `scans` - Scan results and metadata
- `scan_queue` - Pending scan jobs
- `scan_vulnerabilities` - Detected vulnerabilities
- `scan_grade_degradations` - Grade calculation details

### Authentication Tables (Used when AUTH_MODE != none)
- `users` - User accounts
- `refresh_tokens` - JWT refresh tokens
- `audit_log` - Admin action logging
- `api_keys` - Programmatic access keys

### Admin Tables
- `data_retention_policies` - Automated cleanup settings
- `system_config` - Runtime configuration
- `schema_version` - Database version tracking
- `migration_history` - Upgrade audit trail

## Migration Guide

### Checking Your Version

```bash
# Automated check with upgrade prompt
./scripts/check-schema-version.sh

# Manual check
docker-compose exec postgres psql -U postgres -d tlsscanner -c "SELECT * FROM schema_version;"
```

### Fresh Installation

For new deployments:

```bash
# Start PostgreSQL
docker-compose up -d postgres

# Apply v2 schema
docker-compose exec -T postgres psql -U postgres -d tlsscanner < scripts/schema-v2.sql
```

### Upgrading from v1.x

The upgrade script safely adds new tables without affecting existing data:

```bash
# Backup first (always!)
docker-compose exec postgres pg_dump -U postgres tlsscanner > backup_pre_v2.sql

# Run upgrade
./scripts/check-schema-version.sh
# OR manually:
docker-compose exec -T postgres psql -U postgres -d tlsscanner < scripts/upgrade-v1-to-v2.sql
```

What the upgrade adds:
- Authentication tables (users, tokens, audit_log, api_keys)
- Admin features (data_retention_policies, system_config)
- Version tracking (schema_version, migration_history)
- User tracking columns in scans and scan_queue

### Version Detection Logic

```sql
-- No tables exist → Fresh installation
-- No schema_version table → v1.0.0
-- Has schema_version table → Check recorded version
SELECT version FROM schema_version WHERE id = 1;
```

## Backup and Recovery

### Creating Backups

```bash
# Full database backup
docker-compose exec postgres pg_dump -U postgres tlsscanner > backup_$(date +%Y%m%d_%H%M%S).sql

# Data only (no schema)
docker-compose exec postgres pg_dump -U postgres --data-only tlsscanner > data_$(date +%Y%m%d).sql

# Compressed backup
docker-compose exec postgres pg_dump -U postgres tlsscanner | gzip > backup_$(date +%Y%m%d).sql.gz
```

### Restoring from Backup

```bash
# Drop and recreate database
docker-compose exec postgres psql -U postgres -c "DROP DATABASE IF EXISTS tlsscanner;"
docker-compose exec postgres psql -U postgres -c "CREATE DATABASE tlsscanner;"

# Restore backup
docker-compose exec -T postgres psql -U postgres -d tlsscanner < backup_20250821.sql
```

## Troubleshooting

### Common Issues

#### "Table does not exist" errors
```bash
# Ensure you're on v2 schema
./scripts/check-schema-version.sh
```

#### Migration appears stuck
```bash
# Check migration history
docker-compose exec postgres psql -U postgres -d tlsscanner \
  -c "SELECT * FROM migration_history ORDER BY started_at DESC;"
```

#### Need to start fresh
```bash
# Complete reset (DESTROYS ALL DATA)
docker-compose down -v
docker-compose up -d postgres
docker-compose exec -T postgres psql -U postgres -d tlsscanner < scripts/schema-v2.sql
```

### Manual Version Update

If needed, manually set the version:

```sql
-- Connect to database
docker-compose exec postgres psql -U postgres -d tlsscanner

-- Update version
UPDATE schema_version SET version = '2.0.0' WHERE id = 1;
```

## Schema Files Reference

| File | Purpose | When to Use |
|------|---------|-------------|
| `scripts/schema-v2.sql` | Complete v2 schema | Fresh installations |
| `scripts/upgrade-v1-to-v2.sql` | v1 → v2 upgrade | Existing v1 installations |
| `scripts/check-schema-version.sh` | Version checker | Always - it's smart! |

## Best Practices

1. **Always backup before migrations**
2. **Use check-schema-version.sh** - It detects and handles versions correctly
3. **Test migrations in development first**
4. **Keep auth tables even if not using auth** - Prevents future migration issues
5. **Monitor logs after migration**:
   ```bash
   docker-compose logs postgres
   docker-compose logs api
   ```

## For Developers

### Adding Schema Changes

For future schema modifications:

1. Create new version file: `scripts/schema-v3.sql`
2. Create upgrade script: `scripts/upgrade-v2-to-v3.sql`
3. Update version in new schema:
   ```sql
   UPDATE schema_version SET version = '3.0.0' WHERE id = 1;
   ```
4. Update `check-schema-version.sh` to handle new version
5. Document changes in this file

### Testing Migrations

```bash
# Test fresh install
docker-compose down -v
docker-compose up -d postgres
./scripts/check-schema-version.sh

# Test upgrade path
docker-compose down -v
docker-compose up -d postgres
docker-compose exec -T postgres psql -U postgres -d tlsscanner < scripts/schema.sql  # Install v1
./scripts/check-schema-version.sh  # Should offer v2 upgrade
```

## Related Documentation

- [Configuration Guide](configuration/README.md) - Database connection settings
- [Development Guide](DEVELOPMENT.md) - Local database setup
- [API Documentation](api/README.md) - Database-backed endpoints