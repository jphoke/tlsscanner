#!/bin/bash
#
# Generate a self-signed certificate for TLS Scanner Portal
# This is suitable for development, testing, and internal deployments
#
# For production use with public domains, consider Let's Encrypt instead
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SSL_DIR="$PROJECT_ROOT/ssl"
CERT_DIR="$SSL_DIR/certs"
KEY_DIR="$SSL_DIR/private"

printf "${GREEN}TLS Scanner Portal - Self-Signed Certificate Generator${NC}\n"
echo ""

# Check if openssl is installed
if ! command -v openssl &> /dev/null; then
    printf "${RED}Error: openssl is not installed${NC}\n"
    echo "Please install openssl first:"
    echo "  Ubuntu/Debian: sudo apt-get install openssl"
    echo "  macOS: brew install openssl"
    echo "  RHEL/CentOS: sudo yum install openssl"
    exit 1
fi

# Create directories if they don't exist
mkdir -p "$CERT_DIR" "$KEY_DIR"

# Default values
DEFAULT_DOMAIN="localhost"
DEFAULT_DAYS=365

# Get user input
printf "${YELLOW}Certificate Configuration:${NC}\n"
echo ""
read -p "Domain name or IP address [$DEFAULT_DOMAIN]: " DOMAIN
DOMAIN=${DOMAIN:-$DEFAULT_DOMAIN}

read -p "Validity period in days [$DEFAULT_DAYS]: " DAYS
DAYS=${DAYS:-$DEFAULT_DAYS}

echo ""
printf "${YELLOW}Additional SANs (Subject Alternative Names):${NC}\n"
echo "Enter additional domains/IPs (one per line, empty line to finish):"
echo "Examples: 192.168.1.100, scanner.local, tlsscanner.internal"
echo ""

SANS=""
while true; do
    read -p "SAN: " SAN
    if [ -z "$SAN" ]; then
        break
    fi
    if [ -z "$SANS" ]; then
        SANS="DNS:$SAN"
    else
        SANS="$SANS,DNS:$SAN"
    fi
done

# Build the subject alternative names
if [ -z "$SANS" ]; then
    SAN_EXT="subjectAltName=DNS:$DOMAIN,DNS:localhost,IP:127.0.0.1"
else
    SAN_EXT="subjectAltName=DNS:$DOMAIN,DNS:localhost,IP:127.0.0.1,$SANS"
fi

echo ""
printf "${GREEN}Generating certificate...${NC}\n"
echo "  Domain: $DOMAIN"
echo "  Validity: $DAYS days"
echo "  SANs: $SAN_EXT"
echo ""

# Generate private key and certificate
openssl req -x509 -nodes -days "$DAYS" -newkey rsa:4096 \
    -keyout "$KEY_DIR/tlsscanner.key" \
    -out "$CERT_DIR/tlsscanner.crt" \
    -subj "/C=US/ST=State/L=City/O=TLS Scanner/CN=$DOMAIN" \
    -addext "$SAN_EXT" \
    2>/dev/null

# Set proper permissions
chmod 644 "$CERT_DIR/tlsscanner.crt"
chmod 600 "$KEY_DIR/tlsscanner.key"

printf "${GREEN}✓ Certificate generated successfully!${NC}\n"
echo ""
echo "Files created:"
echo "  Certificate: $CERT_DIR/tlsscanner.crt"
echo "  Private Key: $KEY_DIR/tlsscanner.key"
echo ""
printf "${YELLOW}Certificate Details:${NC}\n"
openssl x509 -in "$CERT_DIR/tlsscanner.crt" -noout -subject -dates -ext subjectAltName

echo ""
printf "${GREEN}Next Steps:${NC}\n"
echo "1. Start or restart the Docker containers:"
printf "   ${YELLOW}docker compose restart nginx${NC}\n"
echo ""
echo "2. Access the portal via HTTPS:"
printf "   ${YELLOW}https://$DOMAIN:3443${NC}\n"
echo ""
printf "${YELLOW}Note:${NC} Browsers will show a security warning for self-signed certificates.\n"
echo "This is expected. You can safely proceed by accepting the certificate."
echo ""
echo "To avoid warnings in development:"
echo "  - Chrome/Edge: Type 'thisisunsafe' when you see the warning"
echo "  - Firefox: Click 'Advanced' → 'Accept the Risk and Continue'"
echo "  - Import the certificate to your system's trusted root certificates"
