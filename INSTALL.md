# Installation Guide

This guide covers all installation options for the TLS Scanner Portal, from quick Docker setup to production deployments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Docker Installation](#quick-docker-installation)
- [Custom Port Configuration](#custom-port-configuration)
- [CLI-Only Installation](#cli-only-installation)
- [Production Installation](#production-installation)
- [Custom CA Configuration](#custom-ca-configuration)
- [Database Maintenance](#database-maintenance)
- [Backup and Recovery](#backup-and-recovery)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Security Hardening](#security-hardening)
- [Next Steps](#next-steps)

## Prerequisites

### Minimum Requirements
- Docker 20.10+ and Docker Compose v2
- 2 CPU cores
- 2GB RAM (4GB recommended)
- 10GB disk space
- Linux, macOS, or Windows with WSL2

### For CLI-only Installation
- Go 1.23+ (if building from source)
- Git

## Quick Docker Installation

The fastest way to get started (covered in README):

```bash
git clone https://github.com/jphoke/tlsscanner
cd tlsscanner
docker compose up -d
```

Access at http://localhost:3000

## Custom Port Configuration

If you have services already running on default ports:

1. Copy the environment template:
```bash
cp .env.example .env
```

2. Edit `.env` to change host ports:
```bash
# Default ports - change these if you have conflicts
POSTGRES_HOST_PORT=5433    # Changed from 5432
REDIS_HOST_PORT=6380       # Changed from 6379
API_HOST_PORT=8001         # Changed from 8000
WEB_HOST_PORT=3001         # Changed from 3000
```

3. Update Swagger host to match:
```bash
SWAGGER_HOST=localhost:8001
```

4. Start with custom configuration:
```bash
docker compose up -d
```

## CLI-Only Installation

### Option 1: Build from Release Archive

Download and build from the latest release:
```bash
# Download latest release source
wget https://github.com/jphoke/tlsscanner/archive/refs/tags/v1.0.1.tar.gz
tar -xzf v1.0.1.tar.gz
cd tlsscanner-1.0.1

# Build the scanner
go build -o tlsscanner ./cmd/scanner

# Install to PATH
sudo mv tlsscanner /usr/local/bin/

# Test it
tlsscanner -target example.com
```

### Option 2: Build from Git Repository

```bash
# Clone repository
git clone https://github.com/jphoke/tlsscanner
cd tlsscanner

# Build scanner
go build -o tlsscanner ./cmd/scanner

# Install to PATH
sudo mv tlsscanner /usr/local/bin/

# Test installation
tlsscanner -target example.com
```

### CLI with Custom CA Support

For internal certificates, use the existing `custom-ca` directory:
```bash
# Copy your CA certificates to the custom-ca directory
cp /path/to/internal-ca.crt ./custom-ca/
cp /path/to/intermediate-ca.crt ./custom-ca/

# Use with scanner
tlsscanner -target internal.company.com -ca-path ./custom-ca
```

## Production Installation

### Environment Preparation

1. **Clone and setup:**
```bash
cd /opt
sudo git clone https://github.com/jphoke/tlsscanner
cd /opt/tlsscanner
```

2. **Configure environment:**
```bash
cp .env.example .env
```

Edit `.env` with production values:
```bash
# Set strong passwords
POSTGRES_PASSWORD=<generate-strong-password>
DATABASE_URL=postgres://postgres:<password>@postgres/tlsscanner?sslmode=disable

# Production mode
GIN_MODE=release

# Your domain
DOMAIN=scanner.yourdomain.com
SWAGGER_HOST=scanner.yourdomain.com
```

### Docker Compose Production Setup

1. **Create production override:**
```yaml
# docker-compose.override.yml
version: '3.8'

services:
  api:
    restart: always
    environment:
      - GIN_MODE=release
    
  postgres:
    restart: always
    volumes:
      - postgres_data:/var/lib/postgresql/data
    
  redis:
    restart: always
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

2. **Start services:**
```bash
docker compose up -d
```

### HTTPS/TLS Configuration

The TLS Scanner Portal includes built-in HTTPS support via nginx. By default, the portal serves:
- HTTP on port 3000 (redirects to HTTPS)
- HTTPS on port 3443

#### Quick Setup with Self-Signed Certificate

For development, testing, or internal deployments:

```bash
# Generate a self-signed certificate
./scripts/generate-self-signed-cert.sh

# Restart nginx to load the certificate
docker compose restart nginx

# Access via HTTPS
https://localhost:3443
```

**Note:** Browsers will show a security warning for self-signed certificates. This is expected and safe for internal use.

#### Production Setup with Let's Encrypt

For public-facing deployments with free, trusted certificates:

1. **Install certbot:**
```bash
sudo apt-get update
sudo apt-get install certbot
```

2. **Stop the containers temporarily:**
```bash
docker compose down
```

3. **Generate certificate (certbot needs port 80):**
```bash
sudo certbot certonly --standalone -d scanner.yourdomain.com
```

4. **Copy certificates to the project:**
```bash
sudo cp /etc/letsencrypt/live/scanner.yourdomain.com/fullchain.pem ssl/certs/tlsscanner.crt
sudo cp /etc/letsencrypt/live/scanner.yourdomain.com/privkey.pem ssl/private/tlsscanner.key
sudo chown $USER:$USER ssl/certs/tlsscanner.crt ssl/private/tlsscanner.key
```

5. **Update .env with your domain:**
```bash
cp .env.example .env
# Edit .env and set:
DOMAIN=scanner.yourdomain.com
SWAGGER_HOST=scanner.yourdomain.com
WEB_HOST_PORT=80
WEB_HTTPS_PORT=443
```

6. **Start the containers:**
```bash
docker compose up -d
```

7. **Set up auto-renewal:**
```bash
sudo crontab -e
# Add this line to renew certificates and reload nginx:
0 0 1 * * certbot renew --quiet && cp /etc/letsencrypt/live/scanner.yourdomain.com/*.pem /opt/tlsscanner/ssl/certs/ && docker compose -f /opt/tlsscanner/docker-compose.yml restart nginx
```

#### Production Setup with Commercial Certificate

For production environments requiring trusted certificates from commercial CAs:

1. **Generate a Certificate Signing Request (CSR):**
```bash
./scripts/generate-csr.sh
```

This interactive script will:
- Collect your organization information
- Generate a private key (2048/4096/8192-bit RSA)
- Create a CSR with Subject Alternative Names (SANs)
- Save files to `ssl/tlsscanner.csr` and `ssl/private/tlsscanner.key`

2. **Submit CSR to your Certificate Authority:**

Popular CAs:
- **DigiCert**: https://www.digicert.com (Industry leader, OV/EV certificates)
- **Sectigo**: https://sectigo.com (formerly Comodo, affordable options)
- **GlobalSign**: https://www.globalsign.com (International presence)
- **GoDaddy**: https://www.godaddy.com/web-security/ssl-certificate
- **Entrust**: https://www.entrust.com (Government and enterprise)

Copy the CSR content:
```bash
cat ssl/tlsscanner.csr
# Submit this to your CA's certificate request form
```

3. **Install the signed certificate:**

Once you receive the certificate from your CA:
```bash
# Save the certificate
cat your-signed-cert.crt > ssl/certs/tlsscanner.crt

# IMPORTANT: Include intermediate certificates
# Most CAs provide a bundle or chain file
cat your-signed-cert.crt intermediate.crt > ssl/certs/tlsscanner.crt

# Set proper permissions
chmod 644 ssl/certs/tlsscanner.crt
chmod 600 ssl/private/tlsscanner.key
```

4. **Verify certificate and key match:**
```bash
openssl x509 -noout -modulus -in ssl/certs/tlsscanner.crt | openssl md5
openssl rsa -noout -modulus -in ssl/private/tlsscanner.key | openssl md5
# The MD5 hashes MUST match
```

5. **Update .env for production ports:**
```bash
cp .env.example .env
# Edit .env and set:
DOMAIN=scanner.yourdomain.com
SWAGGER_HOST=scanner.yourdomain.com
WEB_HOST_PORT=80
WEB_HTTPS_PORT=443
```

6. **Restart nginx:**
```bash
docker compose restart nginx
```

7. **Test the certificate:**
```bash
curl -v https://scanner.yourdomain.com
openssl s_client -connect scanner.yourdomain.com:443 -servername scanner.yourdomain.com
```

#### Corporate/Internal CA

For environments with internal Certificate Authorities:

1. **Generate a CSR:**
```bash
openssl req -new -newkey rsa:4096 -nodes \
  -keyout ssl/private/tlsscanner.key \
  -out ssl/tlsscanner.csr \
  -subj "/C=US/ST=State/L=City/O=YourCompany/CN=scanner.internal.com"
```

2. **Submit the CSR to your internal CA**

3. **Save the signed certificate:**
```bash
# Save the certificate received from your CA
cat signed-cert.crt > ssl/certs/tlsscanner.crt

# If your CA provides intermediate certificates, include them:
cat signed-cert.crt intermediate-ca.crt root-ca.crt > ssl/certs/tlsscanner.crt
```

4. **Restart nginx:**
```bash
docker compose restart nginx
```

#### Verify HTTPS Configuration

After setting up certificates:

```bash
# Test the HTTPS endpoint
curl -v https://localhost:3443

# For self-signed certificates, use -k to skip verification:
curl -k -v https://localhost:3443

# Check certificate details
openssl s_client -connect localhost:3443 -servername localhost

# Verify certificate and key match
openssl x509 -noout -modulus -in ssl/certs/tlsscanner.crt | openssl md5
openssl rsa -noout -modulus -in ssl/private/tlsscanner.key | openssl md5
# The MD5 hashes should match
```

#### HTTPS Troubleshooting

**"No such file or directory" error:**
```bash
# Ensure certificates exist
ls -la ssl/certs/tlsscanner.crt ssl/private/tlsscanner.key

# Generate self-signed cert if missing
./scripts/generate-self-signed-cert.sh
```

**"Certificate verify failed":**
- For self-signed: This is expected, use `-k` flag with curl
- For real certificates: Ensure intermediate certificates are included in tlsscanner.crt

**"Permission denied":**
```bash
# Fix permissions
chmod 644 ssl/certs/tlsscanner.crt
chmod 600 ssl/private/tlsscanner.key
```

**Port already in use:**
```bash
# Check what's using port 443
sudo lsof -i :443

# Change the port in .env
WEB_HTTPS_PORT=8443  # Use a different port
```

### Additional Production Hardening

For maximum security in production environments:

## Custom CA Configuration

For environments using internal Certificate Authorities:

### Docker Installation

1. **Add CA certificates to the existing directory:**
```bash
# Copy internal CA certificates
cp /path/to/internal-ca.crt custom-ca/
cp /path/to/intermediate-ca.crt custom-ca/

# For Active Directory Certificate Services
certutil -ca.cert custom-ca/ad-root-ca.crt
```

2. **Configure in `.env`:**
```bash
HOST_CUSTOM_CA_PATH=./custom-ca
SCANNER_VERBOSE=true  # See loaded CAs in logs
```

3. **Verify CAs are loaded:**
```bash
docker compose logs api | grep "Loaded custom CA"
```

### CLI Installation

```bash
# Global CA directory
sudo mkdir -p /etc/tlsscanner/custom-ca
sudo cp /path/to/ca-certs/* /etc/tlsscanner/custom-ca/

# Per-user CA directory  
mkdir -p ~/.tlsscanner/custom-ca
cp /path/to/ca-certs/* ~/.tlsscanner/custom-ca/

# Use with scanner
tlsscanner -target internal.site.com -ca-path /etc/tlsscanner/custom-ca
```

## Database Maintenance

### Cleanup Scripts

The portal includes automated cleanup scripts:

```bash
# Using Makefile
make cleanup-7     # Delete scans older than 7 days
make cleanup-30    # Delete scans older than 30 days
make cleanup-90    # Delete scans older than 90 days
make cleanup-all   # Delete ALL scans (requires confirmation)

# Using script directly
./scripts/docker-db-cleanup.sh 30    # Delete scans older than 30 days
```

### Automated Cleanup

Create a cron job for automatic cleanup:
```bash
# Edit crontab
crontab -e

# Add daily cleanup (runs at 2 AM)
0 2 * * * cd /opt/tlsscanner && ./scripts/docker-db-cleanup.sh 30 >> /var/log/tlsscanner-cleanup.log 2>&1
```

### Manual Database Operations

```bash
# Connect to database
# Note: Container name may vary based on your project directory
docker exec -it tlsscanner-portal-postgres-1 psql -U postgres tlsscanner
# Or use: docker compose exec postgres psql -U postgres tlsscanner

# Check database size
SELECT pg_database_size('tlsscanner') / 1024 / 1024 as size_mb;

# Manual cleanup
DELETE FROM scans WHERE created_at < NOW() - INTERVAL '30 days';
VACUUM FULL ANALYZE;
```

## Backup and Recovery

### Automated Backups

1. **Create backup script:**
```bash
#!/bin/bash
# /opt/tlsscanner/backup.sh

BACKUP_DIR="/backups/tlsscanner"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup database
# Note: Container names depend on your project directory
docker compose exec postgres pg_dump -U postgres tlsscanner | \
  gzip > $BACKUP_DIR/db_$DATE.sql.gz

# Backup configuration
tar -czf $BACKUP_DIR/config_$DATE.tar.gz .env docker-compose.yml

# Keep last 30 days
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/db_$DATE.sql.gz"
```

2. **Schedule backups:**
```bash
chmod +x /opt/tlsscanner/backup.sh
crontab -e
# Add: 0 3 * * * /opt/tlsscanner/backup.sh
```

### Recovery

```bash
# Restore database
gunzip < /backups/tlsscanner/db_20240101_030000.sql.gz | \
  docker compose exec -T postgres psql -U postgres tlsscanner

# Restore configuration
cd /opt/tlsscanner
tar -xzf /backups/tlsscanner/config_20240101_030000.tar.gz
```

## Monitoring

### Health Checks

```bash
# API health
curl http://localhost:8000/api/v1/health

# With custom ports
curl http://localhost:${API_HOST_PORT:-8000}/api/v1/health
```

### Resource Monitoring

```bash
# Container stats
docker stats

# Disk usage
df -h
du -sh /var/lib/docker/volumes/

# Database connections
docker compose exec postgres psql -U postgres -c \
  "SELECT count(*) FROM pg_stat_activity WHERE datname = 'tlsscanner';"
```

## Troubleshooting

### Common Issues

**Port conflicts:**
```bash
# Check what's using a port
sudo lsof -i :5432
sudo netstat -tlnp | grep 5432

# Solution: Change ports in .env file
```

**Database connection failed:**
```bash
# Check if postgres is running
docker ps | grep postgres

# Check logs
docker compose logs postgres

# Test connection
docker compose exec postgres psql -U postgres
```

**High memory usage:**
```bash
# Limit container memory (use actual container name from docker ps)
docker update --memory="1g" tlsscanner-portal-api-1

# Or in docker-compose.yml:
services:
  api:
    deploy:
      resources:
        limits:
          memory: 1G
```

### Reset Everything

```bash
# WARNING: This deletes all data
docker compose down -v
docker compose up -d --build
```

## Security Hardening

### Production Checklist

- [ ] Strong passwords in `.env`
- [ ] HTTPS enabled via reverse proxy
- [ ] Firewall configured (only 80/443 open)
- [ ] Regular security updates
- [ ] Automated backups configured
- [ ] Log rotation enabled
- [ ] Resource limits set

### Firewall Configuration

Configure firewall rules on the host machine as appropriate for your environment and security policies. The portal needs inbound access on the configured web and API ports (default: 3000, 8000).

## Next Steps

- Set up monitoring alerts
- Configure log aggregation
- Plan disaster recovery procedures
- Schedule security audits
- Review [API Documentation](docs/API.md) for integration