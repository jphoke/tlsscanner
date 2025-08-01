FROM ubuntu:14.04

# Install old OpenSSL that supports SSL v3
RUN apt-get update && \
    apt-get install -y openssl nginx && \
    apt-get clean

# Generate self-signed certificate
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/nginx-selfsigned.key \
    -out /etc/ssl/certs/nginx-selfsigned.crt \
    -subj "/C=US/ST=Test/L=Test/O=Test/CN=sslv3-test"

# Configure nginx for SSL v3
RUN echo 'server { \n\
    listen 443 ssl; \n\
    server_name _; \n\
    \n\
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt; \n\
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key; \n\
    \n\
    # Enable SSL v3 (INSECURE - FOR TESTING ONLY!) \n\
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2; \n\
    ssl_ciphers "ALL:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4"; \n\
    ssl_prefer_server_ciphers on; \n\
    \n\
    location / { \n\
        return 200 "SSL v3 Test Server\\n"; \n\
        add_header Content-Type text/plain; \n\
    } \n\
}' > /etc/nginx/sites-available/default

EXPOSE 443

CMD ["nginx", "-g", "daemon off;"]