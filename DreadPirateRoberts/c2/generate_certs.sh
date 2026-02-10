#!/bin/bash

# Generate self-signed certificates (in server/ so c2server finds them)
echo "Generating TLS certificates..."
cd server || exit 1

openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
rm -f server.csr

# Copy cert to client so it can verify the server
cp server.crt ../client/

cd ..
echo "Certificates generated successfully!"
echo "server.crt and server.key are in server/"
echo "server.crt has been copied to client/" 