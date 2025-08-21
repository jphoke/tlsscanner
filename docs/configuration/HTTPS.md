# HTTPS Setup Guide for TLS Scanner

This guide walks you through enabling HTTPS for the TLS Scanner portal.

## Quick Start: Self-Signed Certificate (Development/Testing)

### Step 1: Copy nginx configuration template
```bash
# If you haven't already
cp nginx.conf.example nginx.conf
```

### Step 2: Generate a self-signed certificate
```bash
cd nginx/certs/
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout tlsscanner.key \
  -out tlsscanner.crt \
  -subj "/C=US/ST=State/L=City/O=Company/CN=localhost"
```

### Step 3: Edit nginx.conf
1. Open `nginx.conf` (not the .example file)
2. Find the section labeled "HTTPS Server (Port 443) - CURRENTLY DISABLED"
3. Uncomment the entire `server { ... }` block (remove the `#` at the start of each line)
4. Change `server_name localhost;` to your domain if needed

### Step 4: Restart nginx
```bash
docker-compose restart nginx
```

### Step 5: Access via HTTPS
Visit: https://localhost:3443 (or your configured port)

---

## Production Setup: Real Certificate from CA

### Step 1: Copy nginx configuration template
```bash
# If you haven't already
cp nginx.conf.example nginx.conf
```

### Step 2: Generate a Certificate Signing Request (CSR)
```bash
cd nginx/certs/

# Generate private key
openssl genrsa -out tlsscanner.key 2048

# Generate CSR
openssl req -new -key tlsscanner.key -out tlsscanner.csr
```

### Step 3: Get certificate from your CA
1. Submit the `tlsscanner.csr` to your Certificate Authority
2. Save the signed certificate as `tlsscanner.crt`
3. If provided, save intermediate certificates as `ca-chain.crt`

### Step 4: Place certificates
```bash
nginx/certs/
├── tlsscanner.crt      # Your certificate
├── tlsscanner.key      # Your private key
└── ca-chain.crt        # Intermediate certificates (if any)
```

### Step 5: Configure nginx.conf
1. Open `nginx.conf` (not the .example file)
2. Uncomment the HTTPS server block
3. Update `server_name` to your actual domain
4. If you have intermediate certs, uncomment:
   ```nginx
   ssl_trusted_certificate /etc/nginx/certs/ca-chain.crt;
   ```

### Step 6: Enable HTTP to HTTPS redirect (optional)
In the HTTP server block, uncomment:
```nginx
return 301 https://$server_name$request_uri;
```
And comment out the location blocks below it.

### Step 7: Restart and test
```bash
docker-compose restart nginx
```

---

## Let's Encrypt Setup (Free Automatic Certificates)

### Prerequisites
- A public domain name pointing to your server
- Port 80 accessible from the internet

### Step 1: Initial certificate
```bash
# Create required directories
mkdir -p certbot/conf certbot/www

# Get initial certificate
docker run -it --rm \
  -v "$(pwd)/certbot/conf:/etc/letsencrypt" \
  -v "$(pwd)/certbot/www:/var/www/certbot" \
  certbot/certbot certonly \
  --webroot \
  --webroot-path=/var/www/certbot \
  --email your-email@example.com \
  --agree-tos \
  --no-eff-email \
  -d yourdomain.com
```

### Step 2: Update nginx.conf
1. Uncomment the "Let's Encrypt Support" section
2. Update `server_name` to your domain
3. In the HTTPS server block, update certificate paths:
   ```nginx
   ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
   ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
   ```

### Step 3: Add certbot service to docker-compose.yml
Uncomment the certbot service section if you want automatic renewal.

### Step 4: Restart
```bash
docker-compose up -d
```

---

## Troubleshooting

### Browser shows certificate warning
- **Self-signed cert**: This is expected. Add an exception in your browser.
- **Domain mismatch**: Ensure `server_name` in nginx.conf matches your URL
- **Expired cert**: Check certificate dates with:
  ```bash
  openssl x509 -in nginx/certs/tlsscanner.crt -noout -dates
  ```

### nginx won't start
Check nginx logs:
```bash
docker-compose logs nginx
```

Common issues:
- Certificate files not found (check paths and filenames)
- Certificate/key mismatch
- Syntax error in nginx.conf

### Permission denied errors
Ensure certificate files are readable:
```bash
chmod 644 nginx/certs/tlsscanner.crt
chmod 600 nginx/certs/tlsscanner.key  # Private key should be restricted
```

### Testing SSL/TLS configuration
After setup, you can test your HTTPS configuration using... the TLS Scanner itself!
```bash
./tlsscanner -target yourdomain.com:443
```

---

## Security Notes

1. **Never commit private keys to git** - The `.gitignore` is configured to exclude certificate files
2. **Use strong ciphers** - The provided nginx.conf uses modern, secure cipher suites
3. **Enable HSTS** - The config includes Strict-Transport-Security header
4. **Regular updates** - Renew certificates before expiry (Let's Encrypt: every 90 days)
5. **Test your configuration** - Use online tools or the TLS Scanner itself to verify

---

## Environment Variables

Configure these in your `.env` file:

```env
# Enable HTTPS mode
HTTPS_MODE=https

# HTTPS port (default 3443 to avoid conflicts)
WEB_HTTPS_PORT=3443

# Domain name (for production)
DOMAIN_NAME=tlsscanner.yourdomain.com
```