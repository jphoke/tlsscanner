# Configuration Guide

Complete configuration reference for TLS Scanner Portal.

## Quick Start

The application uses environment variables for configuration. Copy `.env.example` to `.env` and customize as needed:

```bash
cp .env.example .env
# Edit .env with your settings
docker-compose up -d
```

## Configuration Categories

### [Authentication Setup](AUTH.md)
- User authentication (local or LDAP/AD)
- Role-based access control
- API keys and tokens
- Audit logging

### [HTTPS/TLS Setup](HTTPS.md)
- SSL certificate configuration
- Let's Encrypt integration
- Custom CA certificates
- Security headers

### [Database Configuration](../DATABASE.md)
- Connection settings
- Schema versioning
- Migration procedures
- Backup strategies

## Environment Variables Reference

### Core Settings

```env
# Database
DATABASE_URL=postgres://user:password@host/database
POSTGRES_HOST_PORT=5432

# Redis
REDIS_URL=redis:6379
REDIS_HOST_PORT=6379

# API & Web Ports
API_HOST_PORT=8000
WEB_HOST_PORT=3000
WEB_HTTPS_PORT=3443

# Swagger Documentation
SWAGGER_HOST=localhost:8000
```

### Scanner Configuration

```env
# Timeouts (seconds)
SCAN_TIMEOUT=30
CONNECT_TIMEOUT=10

# Concurrency
MAX_CONCURRENT_SCANS=10
WORKER_COUNT=3

# Debugging
SCANNER_VERBOSE=false
GIN_MODE=release  # debug, test, or release
```

### Authentication Settings

```env
# Authentication Mode
AUTH_MODE=none  # Options: none, optional, required

# When AUTH_MODE != none:
AUTH_PROVIDER=local  # Options: local, ldap
JWT_SECRET=your-secret-key
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h

# LDAP Settings (when AUTH_PROVIDER=ldap)
LDAP_URL=ldap://ad.company.com:389
LDAP_BIND_DN=CN=service,DC=company,DC=com
LDAP_BIND_PASSWORD=password
# ... see AUTH.md for complete LDAP configuration
```

### HTTPS Configuration

```env
# HTTPS Mode
HTTPS_MODE=http  # Options: http, https, auto

# Custom Certificates (when HTTPS_MODE=https)
DOMAIN_NAME=tlsscanner.company.com
SSL_CERT_PATH=/etc/nginx/certs/server.crt
SSL_KEY_PATH=/etc/nginx/certs/server.key

# Let's Encrypt (when HTTPS_MODE=auto)
LETSENCRYPT_EMAIL=admin@company.com
# ... see HTTPS.md for complete SSL configuration
```

### Custom CA Support

```env
# For scanning internal certificates
HOST_CUSTOM_CA_PATH=./custom-ca
CUSTOM_CA_PATH=/certs/custom-ca
```

Place your CA certificates in `./custom-ca/` directory.

### Admin Features

```env
# Data Retention (when AUTH_MODE != none)
SCAN_DATA_RETENTION_DAYS=90
AUDIT_LOG_RETENTION_DAYS=365
AUTO_PRUNE_ENABLED=false

# Export Settings
MAX_EXPORT_RECORDS=10000
EXPORT_FORMAT=json
```

## Configuration Precedence

1. Environment variables (highest priority)
2. `.env` file
3. Default values in code (lowest priority)

## Docker Compose Variables

The `docker-compose.yml` file uses these variables for container configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_HOST_PORT` | 5432 | PostgreSQL host port |
| `REDIS_HOST_PORT` | 6379 | Redis host port |
| `API_HOST_PORT` | 8000 | API service host port |
| `WEB_HOST_PORT` | 3000 | Web UI HTTP port |
| `WEB_HTTPS_PORT` | 3443 | Web UI HTTPS port |

## Security Best Practices

1. **Never commit `.env` to version control** - Use `.env.example` as template
2. **Use strong passwords** - Especially for database and JWT secrets
3. **Rotate secrets regularly** - JWT secrets, API keys, passwords
4. **Restrict file permissions**:
   ```bash
   chmod 600 .env
   chmod 600 nginx/certs/*.key
   ```
5. **Use HTTPS in production** - See [HTTPS Setup](HTTPS.md)
6. **Enable authentication for public deployments** - See [Auth Setup](AUTH.md)

## Validation

Check your configuration:

```bash
# Verify environment variables are loaded
docker-compose config

# Test database connection
docker-compose exec api sh -c 'echo $DATABASE_URL'

# Check service health
curl http://localhost:8000/api/v1/health
```

## Troubleshooting

### Services won't start
- Check `.env` file exists and is readable
- Verify all required variables are set
- Check port conflicts: `netstat -an | grep -E '(3000|8000|5432|6379)'`

### Authentication not working
- Ensure `AUTH_MODE` is set correctly
- For LDAP: Test connection with `ldapsearch`
- Check JWT_SECRET is set and consistent

### HTTPS issues
- Verify certificate files exist in `nginx/certs/`
- Check certificate permissions (readable by nginx)
- Ensure domain name matches certificate

## Related Documentation

- [Authentication Setup](AUTH.md) - Detailed auth configuration
- [HTTPS Setup](HTTPS.md) - SSL/TLS configuration
- [Database Setup](../DATABASE.md) - Database configuration
- [Development Guide](../DEVELOPMENT.md) - Local development setup