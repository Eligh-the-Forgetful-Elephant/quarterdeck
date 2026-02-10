#!/bin/bash

# Use default GOROOT (e.g. Homebrew) if env has invalid GOROOT (e.g. from g-install when ~/.go missing)
if [ -n "$GOROOT" ] && [ ! -d "$GOROOT" ]; then unset GOROOT; fi

# Make scripts executable
chmod +x generate_certs.sh

# Generate TLS certificates
echo "Generating TLS certificates..."
./generate_certs.sh

# Build Go server
echo "Building Go server..."
cd server
go build -o c2server
if [ $? -ne 0 ]; then
    echo "Failed to build Go server"
    exit 1
fi
cd ..

# Build Go client
echo "Building Go client..."
cd client
go build -o client
if [ $? -ne 0 ]; then
    echo "Failed to build Go client"
    exit 1
fi
cd ..

echo "Build complete!"
echo "To run the server: cd server && ./c2server"
echo "To run the client: cd client && ./client" 