# Migration Guide

This guide helps you migrate from older versions of TLS Scanner to the latest version.

## Migrating to Version 1.2.0 (August 2025)

Version 1.2.0 adds optional SSL v3 detection using raw sockets, enhanced vulnerability detection with zcrypto, and ROBOT attack detection.

### Database Migration Required

If you're upgrading from a version before SSL v3 support, you need to update your database schema.

#### Option 1: Using Docker Compose (Recommended)

```bash
# Apply the migration
docker exec tlsscanner-postgres-1 psql -U postgres -d tlsscanner -f /scripts/migration_add_sslv3_check.sql

# Or if you have the migration file locally:
docker exec tlsscanner-postgres-1 psql -U postgres -d tlsscanner -c "$(cat scripts/migration_add_sslv3_check.sql)"
```

#### Option 2: Direct Database Connection

```bash
# Connect to your database
psql -h localhost -U postgres -d tlsscanner

# Run the migration
\i scripts/migration_add_sslv3_check.sql
```

#### Option 3: Manual SQL

If you prefer to run the SQL manually:

```sql
-- Add check_sslv3 column to scans table
ALTER TABLE scans 
ADD COLUMN IF NOT EXISTS check_sslv3 BOOLEAN DEFAULT FALSE;

-- Add check_sslv3 column to scan_queue table  
ALTER TABLE scan_queue
ADD COLUMN IF NOT EXISTS check_sslv3 BOOLEAN DEFAULT FALSE;

-- Add index for filtering scans by SSL v3 check status
CREATE INDEX IF NOT EXISTS idx_scans_check_sslv3 ON scans(check_sslv3) WHERE check_sslv3 = TRUE;
```

### Application Updates

After applying the database migration:

1. **Rebuild the containers**:
   ```bash
   docker-compose build
   docker-compose up -d
   ```

2. **Verify the migration**:
   - Navigate to the web UI
   - You should see a "Deep Scan (includes SSL v3 detection)" checkbox
   - Test a scan with the checkbox enabled

### New Features

- **Deep Scan Option**: Enable SSL v3 detection via raw sockets
- **Automatic F Grade**: Any server supporting SSL v3 receives an automatic F grade
- **Enhanced Vulnerability Detection**: POODLE attack detection for SSL v3
- **CLI Support**: Use `--check-sslv3` flag with the scanner CLI

### Breaking Changes

None. The SSL v3 detection is opt-in and doesn't affect existing functionality.

## Migrating from Standard Go crypto/tls to zcrypto

If you're upgrading from a very old version that still uses Go's standard crypto/tls:

1. The scanner now uses zcrypto for enhanced vulnerability detection
2. All import paths have changed from `crypto/tls` to `github.com/zmap/zcrypto/tls`
3. No action required - this is handled internally

## General Migration Steps

For any migration:

1. **Backup your database**:
   ```bash
   docker exec tlsscanner-postgres-1 pg_dump -U postgres tlsscanner > backup_$(date +%Y%m%d).sql
   ```

2. **Stop the application**:
   ```bash
   docker-compose down
   ```

3. **Pull latest changes**:
   ```bash
   git pull origin main
   ```

4. **Apply any database migrations** (see version-specific sections above)

5. **Rebuild and restart**:
   ```bash
   docker-compose build
   docker-compose up -d
   ```

6. **Verify the deployment**:
   ```bash
   docker-compose ps
   curl http://localhost:8000/api/v1/health
   ```

## Troubleshooting

### "column does not exist" errors

If you see errors like `pq: column "check_sslv3" does not exist`:
- The database migration hasn't been applied
- Follow the database migration steps above

### SSL v3 not being detected

Ensure:
1. You're using the "Deep Scan" option in the UI or `--check-sslv3` flag in CLI
2. The target actually supports SSL v3 (very rare nowadays)
3. Check scanner logs with `SCANNER_VERBOSE=true` for debugging

### Performance considerations

SSL v3 detection uses raw sockets and adds a small overhead:
- Normal scan: ~1-2 seconds
- Deep scan with SSL v3 check: ~2-3 seconds
- Only enable when specifically needed

## Version History

- **v1.2.0 (August 2025)**: SSL v3 raw socket detection, zcrypto migration, ROBOT attack detection, FTP STARTTLS
- **v1.0.1 (July 2025)**: Custom CA support, configurable ports, vulnerability detection
- **v1.0.0 (July 2025)**: Initial release with SSL Labs grading, STARTTLS support