# SSL/TLS Certificates

This directory contains SSL/TLS certificates for serving the TLS Scanner Portal over HTTPS.

## Directory Structure

```
ssl/
├── certs/          # Certificate files (.crt, .pem)
└── private/        # Private key files (.key, .pem)
```

## Certificate Options

### Option 1: Self-Signed Certificate (Development/Testing)

Use the provided script to generate a self-signed certificate:

```bash
./scripts/generate-self-signed-cert.sh
```

This creates:
- `ssl/certs/tlsscanner.crt` - Self-signed certificate
- `ssl/private/tlsscanner.key` - Private key

**Note:** Browsers will show a security warning for self-signed certificates. This is expected and safe for development/internal use.

### Option 2: Let's Encrypt (Production)

For public-facing deployments, use Let's Encrypt with certbot:

```bash
# Install certbot
sudo apt-get install certbot

# Generate certificate (standalone mode - requires port 80 available)
sudo certbot certonly --standalone -d scanner.yourdomain.com

# Copy certificates to ssl directory
sudo cp /etc/letsencrypt/live/scanner.yourdomain.com/fullchain.pem ssl/certs/tlsscanner.crt
sudo cp /etc/letsencrypt/live/scanner.yourdomain.com/privkey.pem ssl/private/tlsscanner.key
sudo chown $USER:$USER ssl/certs/tlsscanner.crt ssl/private/tlsscanner.key
```

**Auto-renewal:** Set up a cron job to renew certificates:
```bash
0 0 1 * * certbot renew --quiet && cp /etc/letsencrypt/live/scanner.yourdomain.com/*.pem /opt/tlsscanner/ssl/certs/
```

### Option 3: Commercial Certificate (DigiCert, Sectigo, etc.)

For production environments requiring trusted certificates:

1. **Generate a Certificate Signing Request (CSR):**
   ```bash
   ./scripts/generate-csr.sh
   ```
   This interactive script will:
   - Create a private key (2048, 4096, or 8192-bit RSA)
   - Generate a CSR with your organization details
   - Support multiple Subject Alternative Names (SANs)
   - Provide the CSR file to submit to your CA

2. **Submit the CSR to your Certificate Authority:**
   - DigiCert: https://www.digicert.com
   - Sectigo: https://sectigo.com
   - GlobalSign: https://www.globalsign.com
   - GoDaddy, Entrust, or any other CA

3. **Install the signed certificate:**
   ```bash
   # Save the certificate from your CA
   cat your-cert.crt > ssl/certs/tlsscanner.crt

   # If you have intermediate certificates, concatenate them:
   cat your-cert.crt intermediate.crt root.crt > ssl/certs/tlsscanner.crt
   ```

4. **Verify the certificate matches the private key:**
   ```bash
   openssl x509 -noout -modulus -in ssl/certs/tlsscanner.crt | openssl md5
   openssl rsa -noout -modulus -in ssl/private/tlsscanner.key | openssl md5
   # The MD5 hashes should match
   ```

### Option 4: Internal CA

For corporate/internal environments with their own CA:

1. Generate a certificate signing request (CSR):
   ```bash
   openssl req -new -newkey rsa:4096 -nodes \
     -keyout ssl/private/tlsscanner.key \
     -out ssl/tlsscanner.csr \
     -subj "/C=US/ST=State/L=City/O=Organization/CN=scanner.company.com"
   ```

2. Submit the CSR to your internal CA

3. Save the signed certificate to `ssl/certs/tlsscanner.crt`

## File Permissions

Ensure correct permissions for security:

```bash
chmod 644 ssl/certs/*.crt
chmod 600 ssl/private/*.key
```

## Verification

After setting up certificates, verify them:

```bash
# Check certificate details
openssl x509 -in ssl/certs/tlsscanner.crt -text -noout

# Verify certificate matches private key
openssl x509 -noout -modulus -in ssl/certs/tlsscanner.crt | openssl md5
openssl rsa -noout -modulus -in ssl/private/tlsscanner.key | openssl md5
# The MD5 hashes should match

# Test the server
curl -v https://localhost:443
```

## Troubleshooting

**"No such file or directory" error:**
- Make sure certificate files exist with the correct names
- Check file permissions (nginx needs read access)

**"Certificate verify failed":**
- For self-signed: Expected, use `-k` flag: `curl -k https://localhost`
- For real certs: Check that intermediate certificates are included

**"Permission denied":**
- Fix permissions: `chmod 644 ssl/certs/*.crt && chmod 600 ssl/private/*.key`
- Ensure Docker has read access to the ssl directory
