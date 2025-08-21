# TLS Scanner Admin Authentication & HTTPS Design

## Overview
This document outlines the implementation plan for administrative authentication and HTTPS/TLS configuration for the TLS Scanner portal.

## Deployment Scenarios

### Scenario 1: Internal Network with Jump Box (Your Use Case)
```env
AUTH_MODE=none                    # No authentication required
USE_LETSENCRYPT=false             # Internal network
# Access controlled via network security/jump box
# All features available without login
# Perfect for IT teams behind corporate firewall
```

### Scenario 2: Enterprise with Active Directory
```env
AUTH_MODE=optional                # Public scanning, admin requires auth
AUTH_PROVIDER=ldap                # Use existing AD infrastructure
LDAP_URL=ldap://dc.company.local:389
ALLOW_ANONYMOUS_SCANS=true        # IT teams can scan without login
# Admin functions require AD group membership
# Leverages existing enterprise identity management
```

### Scenario 3: Semi-Public Deployment
```env
AUTH_MODE=optional                # Mixed access
AUTH_PROVIDER=local               # Self-contained user management
ALLOW_ANONYMOUS_SCANS=true        # Public can scan
USE_LETSENCRYPT=true              # Public TLS certificate
# Anyone can scan, admins must authenticate
```

### Scenario 4: Fully Secured Internet-Facing
```env
AUTH_MODE=required                # All features require login
AUTH_PROVIDER=local               # Or ldap for enterprise
ALLOW_ANONYMOUS_SCANS=false       # No public access
USE_LETSENCRYPT=true              # Public TLS certificate
# Complete access control
```

## Authentication Strategy

### Chosen Approach: JWT with Refresh Tokens
After considering options, JWT provides the best balance for this application:
- **Stateless**: Scales well, works with multiple API instances
- **Secure**: Short-lived access tokens (15 min) + longer refresh tokens (7 days)
- **Simple**: No session store needed beyond refresh token tracking
- **API-friendly**: Works well with both web UI and potential CLI admin tools

### Alternative Considered
- **Session-based**: Requires sticky sessions or shared session store
- **OAuth2/OIDC**: Overkill for internal admin tool, adds complexity

## Database Schema Changes

### New Tables

```sql
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Audit log for admin actions
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- API keys for programmatic access (optional)
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    last_used TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at DESC);
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
```

## Authentication Configuration

### Authentication Modes
The system supports multiple authentication modes, configurable via environment variables:

1. **`AUTH_MODE=none`** (Default)
   - No authentication required
   - All features accessible
   - Suitable for internal networks with network-level security
   - Recommended for jump box/bastion host deployments

2. **`AUTH_MODE=optional`**
   - Public features (scanning, viewing) available without login
   - Admin features require authentication
   - Good for semi-public deployments

3. **`AUTH_MODE=required`**
   - All features require authentication
   - Suitable for internet-facing deployments

### Authentication Providers

#### Local Authentication
- Username/password stored in database
- Bcrypt password hashing
- Self-contained, no external dependencies

#### Active Directory/LDAP Integration
```env
# AD/LDAP Configuration
AUTH_PROVIDER=ldap
LDAP_URL=ldap://ad.company.com:389
LDAP_BIND_DN=CN=svc_tlsscanner,CN=Users,DC=company,DC=com
LDAP_BIND_PASSWORD=<service-account-password>
LDAP_BASE_DN=DC=company,DC=com
LDAP_USER_FILTER=(&(objectClass=user)(sAMAccountName=%s))
LDAP_GROUP_FILTER=(&(objectClass=group)(member=%s))

# Group to Role Mapping
LDAP_GROUP_SUPER_ADMIN=CN=TLS_Scanner_SuperAdmins,CN=Groups,DC=company,DC=com
LDAP_GROUP_ADMIN=CN=TLS_Scanner_Admins,CN=Groups,DC=company,DC=com
LDAP_GROUP_OPERATOR=CN=TLS_Scanner_Operators,CN=Groups,DC=company,DC=com
LDAP_GROUP_VIEWER=CN=TLS_Scanner_Viewers,CN=Groups,DC=company,DC=com

# Optional: Use LDAPS (LDAP over TLS)
LDAP_USE_TLS=true
LDAP_TLS_SKIP_VERIFY=false
LDAP_TLS_CA_CERT=/path/to/ca.crt
```

## Role-Based Access Control (RBAC)

### Roles (When Authentication is Enabled)
1. **super_admin**: Full system access
   - User management (create, modify, delete users)
   - System configuration
   - Database maintenance
   - View all scans
   - Delete any scan data
   - Configure authentication settings

2. **admin**: Administrative access
   - View all scans
   - Delete scan data (with audit)
   - Export data
   - Configure scan settings
   - Cannot manage users or auth settings

3. **operator**: Operational access
   - Perform scans
   - View all scans
   - Export own scan data
   - Cannot delete data

4. **viewer**: Read-only access
   - View all scans
   - Cannot perform new scans (when AUTH_MODE=required)
   - Cannot delete or modify data

### Public Access (When AUTH_MODE=none or AUTH_MODE=optional)
- Perform scans
- View scan results
- Access documentation
- No access to admin functions

## Admin Functionality

### Core Admin Features
1. **User Management**
   - Create/edit/delete users
   - Reset passwords
   - Activate/deactivate accounts
   - Change roles

2. **Data Management**
   - Bulk delete old scans (e.g., older than X days)
   - Export scan data
   - Database statistics
   - Purge specific targets

3. **System Monitoring**
   - Active scan queue
   - System health metrics
   - Recent scan statistics
   - Error logs

4. **Audit Trail**
   - All admin actions logged
   - Searchable audit history
   - IP and user agent tracking

## API Authentication Middleware

### JWT Implementation
```go
// Middleware structure
type AuthMiddleware struct {
    jwtSecret     []byte
    skipPaths     []string  // Public endpoints
    roleRequired  string    // Minimum role for endpoint
}

// Token claims
type Claims struct {
    UserID   string `json:"user_id"`
    Username string `json:"username"`
    Email    string `json:"email"`
    Role     string `json:"role"`
    jwt.StandardClaims
}
```

### API Endpoint Protection

#### Always Public (Regardless of AUTH_MODE)
```
GET    /api/v1/health            - System health check
GET    /api/v1/docs              - API documentation
```

#### Conditionally Protected (Based on AUTH_MODE)
```
# When AUTH_MODE=none: All public
# When AUTH_MODE=optional: Public
# When AUTH_MODE=required: Authentication required

GET    /api/v1/scans             - List scans
POST   /api/v1/scans             - Perform scan
GET    /api/v1/scans/:id         - Get scan result
WS     /api/v1/ws                - WebSocket for real-time updates
```

#### Always Protected (When authentication is enabled)
```
# Authentication endpoints (only available when AUTH_MODE != none)
POST   /api/v1/auth/login        - Login (local or LDAP)
POST   /api/v1/auth/refresh      - Refresh token
POST   /api/v1/auth/logout       - Logout

# Admin endpoints (require authentication and appropriate role)
GET    /api/v1/admin/users       - Role: admin
POST   /api/v1/admin/users       - Role: super_admin
PUT    /api/v1/admin/users/:id   - Role: super_admin
DELETE /api/v1/admin/users/:id   - Role: super_admin

DELETE /api/v1/admin/scans/bulk  - Role: admin
POST   /api/v1/admin/scans/purge - Role: admin
GET    /api/v1/admin/stats       - Role: admin
GET    /api/v1/admin/audit       - Role: admin
GET    /api/v1/admin/config      - Role: super_admin
PUT    /api/v1/admin/config      - Role: super_admin
```

## HTTPS/TLS Configuration

### Nginx HTTPS Options

#### Option 1: Let's Encrypt with Certbot (Recommended for Internet-facing)
```nginx
server {
    listen 80;
    server_name tlsscanner.example.com;
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://$server_name$request_uri;
    }
    
    # Certbot challenge
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
}

server {
    listen 443 ssl http2;
    server_name tlsscanner.example.com;
    
    # Certbot certificates
    ssl_certificate /etc/letsencrypt/live/tlsscanner.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tlsscanner.example.com/privkey.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # ... rest of config
}
```

#### Option 2: Custom CA Certificate (For internal/enterprise)
```nginx
server {
    listen 443 ssl http2;
    server_name tlsscanner.internal.company.com;
    
    # Custom certificates
    ssl_certificate /etc/nginx/certs/tlsscanner.crt;
    ssl_certificate_key /etc/nginx/certs/tlsscanner.key;
    
    # If using intermediate CA
    ssl_trusted_certificate /etc/nginx/certs/ca-chain.crt;
    
    # ... rest of config
}
```

### Docker Compose Updates

```yaml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/certs:/etc/nginx/certs:ro
      - ./certbot/conf:/etc/letsencrypt:ro
      - ./certbot/www:/var/www/certbot:ro
      - ./web/static:/usr/share/nginx/html
    depends_on:
      - api
    command: "/bin/sh -c 'while :; do sleep 6h & wait $${!}; nginx -s reload; done & nginx -g \"daemon off;\"'"

  # Optional: Certbot for Let's Encrypt
  certbot:
    image: certbot/certbot
    volumes:
      - ./certbot/conf:/etc/letsencrypt
      - ./certbot/www:/var/www/certbot
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew; sleep 12h & wait $${!}; done;'"
```

### Certificate Management Scripts

#### Generate CSR for Enterprise CA
```bash
#!/bin/bash
# scripts/generate-csr.sh

DOMAIN=${1:-tlsscanner.company.com}
mkdir -p nginx/certs

# Generate private key
openssl genrsa -out nginx/certs/tlsscanner.key 2048

# Generate CSR
openssl req -new -key nginx/certs/tlsscanner.key \
    -out nginx/certs/tlsscanner.csr \
    -subj "/C=US/ST=State/L=City/O=Company/CN=$DOMAIN"

echo "CSR generated at nginx/certs/tlsscanner.csr"
echo "Submit this to your CA for signing"
```

#### Initialize Let's Encrypt
```bash
#!/bin/bash
# scripts/init-letsencrypt.sh

DOMAIN=${1:-tlsscanner.example.com}
EMAIL=${2:-admin@example.com}

# Create required directories
mkdir -p certbot/conf
mkdir -p certbot/www

# Get initial certificate
docker-compose run --rm certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email $EMAIL \
    --agree-tos \
    --no-eff-email \
    -d $DOMAIN

# Restart nginx
docker-compose restart nginx
```

## Active Directory/LDAP Implementation

### LDAP Authentication Flow
```go
// pkg/auth/ldap.go
type LDAPAuthenticator struct {
    URL            string
    BindDN         string
    BindPassword   string
    BaseDN         string
    UserFilter     string
    GroupFilter    string
    UseTLS         bool
    GroupMappings  map[string]string  // AD group DN -> role
}

func (l *LDAPAuthenticator) Authenticate(username, password string) (*User, error) {
    // 1. Connect to LDAP server
    // 2. Bind with service account
    // 3. Search for user
    // 4. Attempt bind with user credentials
    // 5. Fetch user groups
    // 6. Map groups to roles
    // 7. Create/update local user record
    // 8. Return user with role
}
```

### Common AD/LDAP Configurations

#### Microsoft Active Directory
```env
LDAP_URL=ldap://dc01.company.local:389
LDAP_USER_FILTER=(&(objectClass=user)(sAMAccountName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
LDAP_GROUP_FILTER=(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=%s))
```

#### OpenLDAP
```env
LDAP_URL=ldap://ldap.company.com:389
LDAP_USER_FILTER=(&(objectClass=inetOrgPerson)(uid=%s))
LDAP_GROUP_FILTER=(&(objectClass=groupOfNames)(member=%s))
```

#### FreeIPA
```env
LDAP_URL=ldap://ipa.company.com:389
LDAP_USER_FILTER=(&(objectClass=person)(uid=%s))
LDAP_GROUP_FILTER=(&(objectClass=groupOfNames)(member=%s))
```

### LDAP Connection Pooling
```go
type LDAPPool struct {
    connections chan *ldap.Conn
    maxSize     int
    factory     func() (*ldap.Conn, error)
}

// Reuse connections for better performance
// Implement health checks and reconnection logic
```

### User Synchronization
- Option to sync AD/LDAP users to local database
- Cache user info for offline access
- Periodic sync for group membership updates
- Handle user deactivation when removed from AD

## Security Considerations

### Password Requirements (Local Auth Only)
- Minimum 12 characters
- At least one uppercase, lowercase, number, special character
- Check against common password list
- Bcrypt with cost factor 12

### JWT Security
- RS256 signing (asymmetric keys)
- Short expiration (15 minutes for access, 7 days for refresh)
- Refresh token rotation on use
- Blacklist/revoke compromised tokens

### Rate Limiting
- Login attempts: 5 per minute per IP
- API calls: 100 per minute per user
- Admin actions: 20 per minute per user

### CORS Configuration
```go
cors.New(cors.Config{
    AllowOrigins:     []string{"https://tlsscanner.example.com"},
    AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
    AllowHeaders:     []string{"Authorization", "Content-Type"},
    ExposeHeaders:    []string{"Content-Length"},
    AllowCredentials: true,
    MaxAge:          12 * time.Hour,
})
```

## Implementation Phases

### Phase 1: Database & Basic Auth (Week 1)
- [ ] Create auth tables migration
- [ ] Implement password hashing
- [ ] Basic login/logout endpoints
- [ ] JWT generation and validation

### Phase 2: Admin UI (Week 2)
- [ ] Login page
- [ ] Admin dashboard
- [ ] User management pages
- [ ] Data pruning interface

### Phase 3: HTTPS Setup (Week 3)
- [ ] Update nginx configuration
- [ ] Certificate management scripts
- [ ] Docker compose updates
- [ ] Documentation

### Phase 4: Advanced Features (Week 4)
- [ ] API key management
- [ ] Audit logging
- [ ] Rate limiting
- [ ] Security headers

## Testing Strategy

### Unit Tests
- Password hashing/validation
- JWT generation/validation
- Role permission checks

### Integration Tests
- Login flow
- Token refresh
- Protected endpoint access
- Admin operations

### Security Tests
- SQL injection attempts
- XSS prevention
- CSRF protection
- Rate limit enforcement

## Deployment Considerations

### Environment Variables
```env
# Authentication Mode
AUTH_MODE=none                    # Options: none, optional, required
AUTH_PROVIDER=local               # Options: local, ldap

# JWT Settings (when AUTH_MODE != none)
JWT_SECRET=<strong-random-secret>
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h
BCRYPT_COST=12

# LDAP/AD Settings (when AUTH_PROVIDER=ldap)
LDAP_URL=ldap://ad.company.com:389
LDAP_BIND_DN=CN=svc_tlsscanner,CN=Users,DC=company,DC=com
LDAP_BIND_PASSWORD=<service-account-password>
LDAP_BASE_DN=DC=company,DC=com
LDAP_USER_FILTER=(&(objectClass=user)(sAMAccountName=%s))
LDAP_GROUP_FILTER=(&(objectClass=group)(member=%s))
LDAP_USE_TLS=true
LDAP_TLS_SKIP_VERIFY=false
LDAP_TLS_CA_CERT=/path/to/ca.crt

# AD Group to Role Mapping
LDAP_GROUP_SUPER_ADMIN=CN=TLS_Scanner_SuperAdmins,CN=Groups,DC=company,DC=com
LDAP_GROUP_ADMIN=CN=TLS_Scanner_Admins,CN=Groups,DC=company,DC=com
LDAP_GROUP_OPERATOR=CN=TLS_Scanner_Operators,CN=Groups,DC=company,DC=com
LDAP_GROUP_VIEWER=CN=Domain Users,CN=Groups,DC=company,DC=com

# Admin Settings
ADMIN_REGISTRATION_ENABLED=false
DEFAULT_ADMIN_EMAIL=admin@company.com
ALLOW_ANONYMOUS_SCANS=true        # When AUTH_MODE=optional

# HTTPS Settings
DOMAIN_NAME=tlsscanner.example.com
SSL_CERT_PATH=/etc/nginx/certs/tlsscanner.crt
SSL_KEY_PATH=/etc/nginx/certs/tlsscanner.key
USE_LETSENCRYPT=false
LETSENCRYPT_EMAIL=admin@example.com
```

### Initial Admin Setup
```bash
# Create first admin user
docker-compose exec api /app/tlsscanner admin create \
    --username admin \
    --email admin@company.com \
    --role super_admin
```

## Monitoring & Maintenance

### Metrics to Track
- Failed login attempts
- Token refresh patterns
- Admin action frequency
- Certificate expiration

### Regular Maintenance
- Rotate JWT secrets quarterly
- Review audit logs monthly
- Purge old refresh tokens weekly
- Certificate renewal (Let's Encrypt: automatic, Custom CA: before expiry)

## Next Steps

1. Review and approve this design
2. Create feature branch `feature/admin-auth`
3. Implement Phase 1 (database and basic auth)
4. Test with development certificates
5. Deploy to staging for testing
6. Production deployment with proper certificates