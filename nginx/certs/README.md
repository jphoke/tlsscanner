# SSL/TLS Certificates Directory

Place your SSL/TLS certificates in this directory for HTTPS support.

## Required Files

When enabling HTTPS (`HTTPS_MODE=https` in .env), place these files here:

- `tlsscanner.crt` - Your server certificate
- `tlsscanner.key` - Your private key (keep this secure!)
- `ca-chain.crt` - (Optional) CA intermediate certificate chain

## File Permissions

Ensure private key has restricted permissions:
```bash
chmod 600 tlsscanner.key
```

## Generating a Self-Signed Certificate (for testing)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout tlsscanner.key \
  -out tlsscanner.crt \
  -subj "/C=US/ST=State/L=City/O=Company/CN=tlsscanner.local"
```

## Generating a Certificate Signing Request (for production)

```bash
# Generate private key
openssl genrsa -out tlsscanner.key 2048

# Generate CSR
openssl req -new -key tlsscanner.key -out tlsscanner.csr \
  -subj "/C=US/ST=State/L=City/O=Company/CN=tlsscanner.yourdomain.com"

# Submit tlsscanner.csr to your CA
# Place the signed certificate as tlsscanner.crt
# Place any intermediate certificates as ca-chain.crt
```

## Security Note

**NEVER commit actual certificates or private keys to git!**

The `.gitignore` file is configured to exclude all files in this directory except this README.