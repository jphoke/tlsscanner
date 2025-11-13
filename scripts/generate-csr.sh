#!/bin/bash
#
# Generate a Certificate Signing Request (CSR) for commercial CAs
# For use with DigiCert, Let's Encrypt, Sectigo, GlobalSign, etc.
#
# This script creates:
#   1. Private key (RSA 4096-bit)
#   2. Certificate Signing Request (CSR)
#
# The CSR can be submitted to your Certificate Authority for signing
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SSL_DIR="$PROJECT_ROOT/ssl"
KEY_DIR="$SSL_DIR/private"
CSR_DIR="$SSL_DIR"

printf "${GREEN}TLS Scanner Portal - Certificate Signing Request (CSR) Generator${NC}\n"
printf "${BLUE}For use with commercial Certificate Authorities${NC}\n"
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
mkdir -p "$KEY_DIR" "$CSR_DIR"

printf "${YELLOW}Certificate Information:${NC}\n"
echo "This information will be included in your certificate."
echo "Ensure accuracy - these details cannot be changed after issuance."
echo ""

# Get Common Name (most important field)
read -p "Common Name (domain name) [scanner.yourdomain.com]: " CN
CN=${CN:-scanner.yourdomain.com}

# Use CN for filenames (sanitize for filesystem)
CERT_NAME="${CN}"

echo ""
printf "${YELLOW}Organization Information:${NC}\n"
echo "This information identifies your organization and must match"
echo "your official registration documents for OV/EV certificates."
echo ""

# Get organization details
read -p "Country Code (2 letters) [US]: " COUNTRY
COUNTRY=${COUNTRY:-US}

read -p "State/Province [California]: " STATE
STATE=${STATE:-California}

read -p "City/Locality [San Francisco]: " CITY
CITY=${CITY:-San Francisco}

read -p "Organization Name [Your Company Inc]: " ORG
ORG=${ORG:-Your Company Inc}

read -p "Organizational Unit (optional) [IT Department]: " OU
OU=${OU:-IT Department}

read -p "Email Address [admin@yourdomain.com]: " EMAIL
EMAIL=${EMAIL:-admin@yourdomain.com}

echo ""
printf "${YELLOW}Subject Alternative Names (SANs):${NC}\n"
echo "Modern certificates require SANs. The Common Name will be automatically included."
echo "Add additional domains/subdomains that this certificate should cover."
echo "Enter one per line, empty line to finish."
echo ""
echo "Examples:"
echo "  scanner.yourdomain.com"
echo "  www.scanner.yourdomain.com"
echo "  tlsscanner.yourdomain.com"
echo ""

SANS="DNS:$CN"
while true; do
    read -p "Additional SAN: " SAN
    if [ -z "$SAN" ]; then
        break
    fi
    # Check if it's an IP address or domain
    if [[ $SAN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SANS="$SANS,IP:$SAN"
    else
        SANS="$SANS,DNS:$SAN"
    fi
done

echo ""
printf "${YELLOW}Key Configuration:${NC}\n"
read -p "Key size in bits [4096]: " KEY_SIZE
KEY_SIZE=${KEY_SIZE:-4096}

# Validate key size
if [[ ! $KEY_SIZE =~ ^(2048|4096|8192)$ ]]; then
    printf "${RED}Error: Key size must be 2048, 4096, or 8192${NC}\n"
    exit 1
fi

echo ""
printf "${GREEN}Generating CSR with the following details:${NC}\n"
echo "  Common Name: $CN"
echo "  Country: $COUNTRY"
echo "  State: $STATE"
echo "  City: $CITY"
echo "  Organization: $ORG"
echo "  Organizational Unit: $OU"
echo "  Email: $EMAIL"
echo "  Key Size: $KEY_SIZE bits"
echo "  SANs: $SANS"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Create a temporary OpenSSL config file with SANs
TEMP_CONFIG=$(mktemp)
cat > "$TEMP_CONFIG" << EOF
[req]
default_bits = $KEY_SIZE
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORG
OU = $OU
CN = $CN
emailAddress = $EMAIL

[req_ext]
subjectAltName = $SANS
EOF

echo ""
printf "${GREEN}Generating private key and CSR...${NC}\n"

# Generate private key and CSR
openssl req -new -newkey rsa:$KEY_SIZE -nodes \
    -keyout "$KEY_DIR/${CERT_NAME}.key" \
    -out "$CSR_DIR/${CERT_NAME}.csr" \
    -config "$TEMP_CONFIG"

# Clean up temp config
rm "$TEMP_CONFIG"

# Set proper permissions
chmod 600 "$KEY_DIR/${CERT_NAME}.key"
chmod 644 "$CSR_DIR/${CERT_NAME}.csr"

echo ""
printf "${GREEN}✓ CSR generated successfully!${NC}\n"
echo ""
echo "Files created:"
echo "  Private Key: $KEY_DIR/${CERT_NAME}.key"
echo "  CSR: $CSR_DIR/${CERT_NAME}.csr"
echo ""

# Display CSR information
printf "${YELLOW}Certificate Request Details:${NC}\n"
openssl req -in "$CSR_DIR/${CERT_NAME}.csr" -noout -text | grep -A1 "Subject:"
openssl req -in "$CSR_DIR/${CERT_NAME}.csr" -noout -text | grep -A10 "Subject Alternative Name:"

echo ""
printf "${GREEN}Next Steps:${NC}\n"
echo ""
printf "1. ${YELLOW}Submit the CSR to your Certificate Authority:${NC}\n"
echo "   File: $CSR_DIR/${CERT_NAME}.csr"
echo ""
echo "   To view the CSR contents:"
printf "   ${BLUE}cat $CSR_DIR/${CERT_NAME}.csr${NC}\n"
echo ""
echo "   To copy to clipboard (macOS):"
printf "   ${BLUE}cat $CSR_DIR/${CERT_NAME}.csr | pbcopy${NC}\n"
echo ""
echo "   To copy to clipboard (Linux with xclip):"
printf "   ${BLUE}cat $CSR_DIR/${CERT_NAME}.csr | xclip -selection clipboard${NC}\n"
echo ""

printf "2. ${YELLOW}Popular Certificate Authorities:${NC}\n"
echo "   - DigiCert: https://www.digicert.com"
echo "   - Sectigo (formerly Comodo): https://sectigo.com"
echo "   - GlobalSign: https://www.globalsign.com"
echo "   - GoDaddy: https://www.godaddy.com/web-security/ssl-certificate"
echo "   - Entrust: https://www.entrust.com"
echo ""

printf "3. ${YELLOW}When you receive the certificate from your CA:${NC}\n"
echo "   Save the certificate to the nginx expected location:"
echo ""
printf "   ${BLUE}# Copy your signed certificate (include intermediates if provided)\n"
printf "   cat ${CERT_NAME}.crt intermediate.crt > $SSL_DIR/certs/tlsscanner.crt${NC}\n"
echo ""
printf "   ${BLUE}# Copy the private key to the nginx expected location\n"
printf "   cp $KEY_DIR/${CERT_NAME}.key $SSL_DIR/private/tlsscanner.key${NC}\n"
echo ""

printf "4. ${YELLOW}Verify the certificate matches the private key:${NC}\n"
printf "   ${BLUE}openssl x509 -noout -modulus -in $SSL_DIR/certs/tlsscanner.crt | openssl md5${NC}\n"
printf "   ${BLUE}openssl rsa -noout -modulus -in $SSL_DIR/private/tlsscanner.key | openssl md5${NC}\n"
echo "   (The MD5 hashes should match)"
echo ""

printf "5. ${YELLOW}Install and test:${NC}\n"
printf "   ${BLUE}docker compose restart nginx${NC}\n"
printf "   ${BLUE}curl -v https://$CN${NC}\n"
echo ""

printf "${YELLOW}Important Security Notes:${NC}\n"
echo "  - Keep $KEY_DIR/${CERT_NAME}.key secure and never share it"
echo "  - Make a backup of the private key in a secure location"
echo "  - The CSR ($CSR_DIR/${CERT_NAME}.csr) can be safely shared with your CA"
echo "  - Some CAs may require additional validation (email, DNS, or file-based)"
echo ""

printf "${GREEN}CSR generation complete!${NC}\n"
