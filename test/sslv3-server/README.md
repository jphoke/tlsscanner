# SSL v3 Test Server

⚠️ **WARNING: This server intentionally uses SSL v3 which is INSECURE and BROKEN. FOR TESTING ONLY!**

## Purpose
This Docker container runs an old nginx with SSL v3 enabled for testing the tlsscanner SSL v3 detection feature.

## Setup

### Option 1: Docker Compose (Recommended)
```bash
cd test/sslv3-server
docker-compose up -d
```

The server will be available on port 18015.

### Option 2: Manual Docker Build
```bash
cd test/sslv3-server
docker build -t sslv3-test .
docker run -d -p 18015:443 --name sslv3-test-server sslv3-test
```

## Testing
Test with tlsscanner:
```bash
./scanner -target localhost:18015 -check-sslv3 -v
```

Test with OpenSSL (if you have an old version):
```bash
openssl s_client -connect localhost:18015 -ssl3
```

## Cleanup
```bash
docker-compose down
# or
docker stop sslv3-test-server
docker rm sslv3-test-server
```

## Deploying to Proxmox
1. Create an LXC container with Ubuntu 14.04 or 16.04
2. Install Docker in the container
3. Copy this directory to the container
4. Run docker-compose up -d
5. Access from your network at <container-ip>:18015

## Security Note
This server is intentionally vulnerable to POODLE and other SSL v3 attacks. 
- Run only on isolated test networks
- Never expose to the internet
- Remove when testing is complete