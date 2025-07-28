# Deployment Guide

This guide covers deploying the TLS Scanner Portal to production environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Deployment Options](#deployment-options)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Cloud Deployments](#cloud-deployments)
- [Configuration](#configuration)
- [Security Considerations](#security-considerations)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Docker and Docker Compose installed
- Domain name (for HTTPS)
- SSL certificate (Let's Encrypt recommended)
- Minimum server requirements:
  - 2 CPU cores
  - 4GB RAM
  - 20GB disk space
  - Ubuntu 20.04+ or similar

## Deployment Options

### Quick Decision Guide

- **Docker Compose**: Best for single-server deployments
- **Kubernetes**: For high availability and scaling
- **Cloud Managed**: For minimal maintenance overhead

## Docker Deployment

### 1. Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sudo sh

# Install Docker Compose
sudo apt install docker-compose-plugin

# Add user to docker group
sudo usermod -aG docker $USER
```

### 2. Clone Repository

```bash
git clone https://github.com/jphoke/tlsscanner
cd tlsscanner/tlsscanner-portal
```

### 3. Production Configuration

Create production environment file:

```bash
cp .env.example .env.production
```

Edit `.env.production`:
```env
# Database
POSTGRES_DB=tlsscanner
POSTGRES_USER=tlsscanner
POSTGRES_PASSWORD=<strong-password>
DATABASE_URL=postgresql://tlsscanner:<strong-password>@postgres:5432/tlsscanner

# Redis
REDIS_URL=redis://redis:6379

# API Configuration
PORT=8080
GIN_MODE=release

# Domain Configuration
DOMAIN=scanner.yourdomain.com
```

### 4. SSL Certificate Setup

#### Option A: Let's Encrypt (Recommended)

```bash
# Install certbot
sudo apt install certbot

# Get certificate
sudo certbot certonly --standalone -d scanner.yourdomain.com

# Certificates will be in:
# /etc/letsencrypt/live/scanner.yourdomain.com/
```

#### Option B: Custom Certificate

Place your certificates in `./certs/`:
- `fullchain.pem` - Certificate chain
- `privkey.pem` - Private key

### 5. Update Nginx Configuration

Edit `configs/nginx.conf`:

```nginx
server {
    listen 80;
    server_name scanner.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name scanner.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/scanner.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/scanner.yourdomain.com/privkey.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    location / {
        proxy_pass http://web:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /api {
        proxy_pass http://api:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 6. Production Docker Compose

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./configs/nginx.conf:/etc/nginx/conf.d/default.conf
      - /etc/letsencrypt:/etc/letsencrypt:ro
    depends_on:
      - api
      - web
    restart: unless-stopped

  web:
    build:
      context: .
      target: web
    expose:
      - "3000"
    restart: unless-stopped

  api:
    build:
      context: .
      target: api
    env_file: .env.production
    expose:
      - "8080"
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    env_file: .env.production
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/schema.sql:/docker-entrypoint-initdb.d/01-schema.sql
    ports:
      - "${POSTGRES_HOST_PORT:-5432}:5432"
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    ports:
      - "${REDIS_HOST_PORT:-6379}:6379"
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

### 7. Deploy

```bash
# Build and start services
docker compose -f docker-compose.prod.yml up -d --build

# Check status
docker compose -f docker-compose.prod.yml ps

# View logs
docker compose -f docker-compose.prod.yml logs -f
```

### 8. Automated Certificate Renewal

Add to crontab:
```bash
sudo crontab -e

# Add this line
0 2 * * * certbot renew --quiet && docker compose -f /path/to/docker-compose.prod.yml restart nginx
```

## Kubernetes Deployment

### 1. Prerequisites

- Kubernetes cluster (1.20+)
- kubectl configured
- Helm 3 installed

### 2. Create Namespace

```bash
kubectl create namespace tlsscanner
```

### 3. Create Secrets

```bash
# Database secret
kubectl create secret generic postgres-secret \
  --from-literal=password=<strong-password> \
  -n tlsscanner

# Redis secret (if using password)
kubectl create secret generic redis-secret \
  --from-literal=password=<redis-password> \
  -n tlsscanner
```

### 4. Deploy with Helm

Create `helm/values.yaml`:

```yaml
replicaCount: 2

image:
  repository: tlsscanner
  tag: latest
  pullPolicy: IfNotPresent

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: scanner.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: tlsscanner-tls
      hosts:
        - scanner.yourdomain.com

postgresql:
  enabled: true
  auth:
    existingSecret: postgres-secret
    database: tlsscanner

redis:
  enabled: true
  auth:
    enabled: false

resources:
  api:
    requests:
      memory: "256Mi"
      cpu: "250m"
    limits:
      memory: "512Mi"
      cpu: "500m"
```

Deploy:
```bash
helm install tlsscanner ./helm -n tlsscanner -f helm/values.yaml
```

## Cloud Deployments

### AWS ECS

1. **Build and Push Images**
```bash
# Build images
docker build -t tlsscanner-api:latest --target api .
docker build -t tlsscanner-web:latest --target web .

# Tag for ECR
docker tag tlsscanner-api:latest <account>.dkr.ecr.<region>.amazonaws.com/tlsscanner-api:latest
docker tag tlsscanner-web:latest <account>.dkr.ecr.<region>.amazonaws.com/tlsscanner-web:latest

# Push to ECR
aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com
docker push <account>.dkr.ecr.<region>.amazonaws.com/tlsscanner-api:latest
docker push <account>.dkr.ecr.<region>.amazonaws.com/tlsscanner-web:latest
```

2. **Create Task Definition** and **Deploy Service** via AWS Console or Terraform

### Google Cloud Run

```bash
# Build and push to Container Registry
gcloud builds submit --tag gcr.io/PROJECT-ID/tlsscanner-api

# Deploy
gcloud run deploy tlsscanner-api \
  --image gcr.io/PROJECT-ID/tlsscanner-api \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars DATABASE_URL=$DATABASE_URL,REDIS_URL=$REDIS_URL
```

### Azure Container Instances

```bash
# Create resource group
az group create --name tlsscanner-rg --location eastus

# Create container instance
az container create \
  --resource-group tlsscanner-rg \
  --name tlsscanner \
  --image tlsscanner-api:latest \
  --dns-name-label tlsscanner \
  --ports 80 443 \
  --environment-variables DATABASE_URL=$DATABASE_URL REDIS_URL=$REDIS_URL
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |
| `PORT` | API server port | `8080` |
| `GIN_MODE` | Gin framework mode | `release` |
| `SCAN_TIMEOUT` | Scanner timeout (seconds) | `30` |
| `MAX_CONCURRENT_SCANS` | Worker pool size | `10` |

### Performance Tuning

```bash
# PostgreSQL tuning (postgresql.conf)
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB

# Redis tuning (redis.conf)
maxmemory 256mb
maxmemory-policy allkeys-lru
```

## Security Considerations

### 1. Network Security

- Use HTTPS only in production
- Implement rate limiting
- Configure firewall rules
- Use private subnets for database/Redis

### 2. API Security

Add API authentication:
```go
// In cmd/api/main.go
r.Use(AuthMiddleware())
```

### 3. Database Security

- Use strong passwords
- Enable SSL for database connections
- Regular backups
- Restrict network access

### 4. Container Security

```dockerfile
# Run as non-root user
USER 1000:1000

# Security scanning
docker scout cves tlsscanner-api:latest
```

## Monitoring

### 1. Health Checks

The API provides health endpoints:
- `/api/v1/health` - Basic health check
- `/api/v1/health/ready` - Readiness probe

### 2. Prometheus Metrics

Add Prometheus endpoint:
```go
import "github.com/prometheus/client_golang/prometheus/promhttp"

r.GET("/metrics", gin.WrapH(promhttp.Handler()))
```

### 3. Logging

Configure structured logging:
```json
{
  "level": "info",
  "time": "2024-01-01T12:00:00Z",
  "message": "Scan completed",
  "target": "example.com",
  "duration": 1.5,
  "grade": "A"
}
```

### 4. Monitoring Stack

```yaml
# docker-compose.monitoring.yml
services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
```bash
# Check PostgreSQL logs
docker logs tlsscanner-postgres

# Test connection
psql $DATABASE_URL -c "SELECT 1"
```

2. **High Memory Usage**
```bash
# Check container stats
docker stats

# Adjust memory limits in docker-compose
```

3. **Slow Scans**
```bash
# Check worker pool size
# Increase MAX_CONCURRENT_SCANS

# Monitor Redis queue
redis-cli -h localhost LLEN scan_queue
```

### Debugging Production Issues

1. **Enable Debug Logging**
```bash
docker exec -it tlsscanner-api sh
export GIN_MODE=debug
# Restart application
```

2. **Database Queries**
```sql
-- Check recent scans
SELECT target, grade, created_at, error 
FROM scans 
ORDER BY created_at DESC 
LIMIT 20;

-- Check scan performance
SELECT target, 
       EXTRACT(EPOCH FROM (completed_at - created_at)) as duration_seconds
FROM scans 
WHERE completed_at IS NOT NULL
ORDER BY duration_seconds DESC
LIMIT 10;
```

3. **Container Debugging**
```bash
# Enter container
docker exec -it tlsscanner-api sh

# Check processes
ps aux

# Network connectivity
ping -c 1 postgres
```

## Backup and Recovery

### Automated Backups

```bash
#!/bin/bash
# backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups"

# Backup database
docker exec tlsscanner-postgres pg_dump -U tlsscanner tlsscanner | gzip > $BACKUP_DIR/tlsscanner_$DATE.sql.gz

# Keep only last 30 days
find $BACKUP_DIR -name "tlsscanner_*.sql.gz" -mtime +30 -delete
```

Add to crontab:
```bash
0 2 * * * /path/to/backup.sh
```

### Restore Procedure

```bash
# Restore database
gunzip < backup.sql.gz | docker exec -i tlsscanner-postgres psql -U tlsscanner tlsscanner
```

## Scaling Considerations

1. **Horizontal Scaling**: Add more API/worker instances
2. **Database**: Consider read replicas for heavy load
3. **Redis**: Use Redis Cluster for high availability
4. **CDN**: Serve static assets via CDN
5. **Load Balancer**: Use cloud load balancer for multiple instances