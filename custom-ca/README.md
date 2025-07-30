# Custom CA Certificates

Place your custom Certificate Authority (CA) certificates in this directory to enable the scanner to trust internally-signed certificates.

## Usage

1. Copy your CA certificate files (`.crt`, `.pem`) to this directory
2. Ensure the directory path is configured in your `.env` file:
   ```
   HOST_CUSTOM_CA_PATH=./custom-ca
   ```
3. The scanner will automatically load and trust these CAs when scanning

## Examples

- Corporate/Enterprise CA certificates
- Development/Testing CA certificates
- Active Directory Certificate Services (AD CS) root certificates

## Note

The scanner will still scan servers with untrusted certificates, but having your custom CAs here ensures proper certificate validation for internal services.