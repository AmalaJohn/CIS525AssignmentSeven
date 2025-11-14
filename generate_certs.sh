#!/bin/bash

# Certificate Generation Script for CIS525 Assignment 7
# Generates CA, Directory Server, and Chat Room certificates

set -e  # Exit on any error

echo "=== Starting Certificate Generation ==="
echo ""

# Clean up old certificates if they exist
echo "Cleaning up old certificates..."
rm -f *.pem *.csr *.srl
echo "Done."
echo ""

# 1. Generate Certificate Authority (CA)
echo "=== Generating Certificate Authority (CA) ==="
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
    -keyout ca-key-temp.pem \
    -out ca-cert.pem \
    -subj "/C=US/ST=Kansas/L=Manhattan/O=KSU/OU=CIS/CN=CIS525-CA"

# Remove password from CA key
openssl rsa -in ca-key-temp.pem -out ca-key.pem
rm -f ca-key-temp.pem

echo "CA certificate and key generated: ca-cert.pem, ca-key.pem"
echo ""

# 2. Generate Directory Server Certificate
echo "=== Generating Directory Server Certificate ==="
# Generate private key
openssl genrsa -out Directory_Server-key-temp.pem 4096

# Remove password from key
openssl rsa -in Directory_Server-key-temp.pem -out Directory_Server-key.pem
rm -f Directory_Server-key-temp.pem

# Generate Certificate Signing Request (CSR)
openssl req -new -key Directory_Server-key.pem \
    -out Directory_Server.csr \
    -subj "/C=US/ST=Kansas/L=Manhattan/O=KSU/OU=CIS/CN=Directory Server"

# Sign with CA
openssl x509 -req -in Directory_Server.csr \
    -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out Directory_Server-cert.pem \
    -days 365

# Clean up CSR
rm -f Directory_Server.csr

echo "Directory Server certificate generated: Directory_Server-cert.pem, Directory_Server-key.pem"
echo ""

# 3. Generate Chat Room Certificates
echo "=== Generating Chat Room Certificates ==="

# Array of chat room topics (only 5 rooms needed)
chat_rooms=(
    "KSU Football"
    "General Chat"
    "Tech Discussion"
    "Study Group"
    "Gaming"
)

for room in "${chat_rooms[@]}"; do
    echo "Generating certificate for: $room"
    
    # Convert room name to filename (replace spaces with underscores)
    filename=$(echo "$room" | tr ' ' '_')
    
    # Generate private key
    openssl genrsa -out "${filename}-key-temp.pem" 4096
    
    # Remove password from key
    openssl rsa -in "${filename}-key-temp.pem" -out "${filename}-key.pem"
    rm -f "${filename}-key-temp.pem"
    
    # Generate CSR with CN set to the chat room name
    openssl req -new -key "${filename}-key.pem" \
        -out "${filename}.csr" \
        -subj "/C=US/ST=Kansas/L=Manhattan/O=KSU/OU=CIS/CN=$room"
    
    # Sign with CA
    openssl x509 -req -in "${filename}.csr" \
        -CA ca-cert.pem -CAkey ca-key.pem \
        -CAcreateserial -out "${filename}-cert.pem" \
        -days 365
    
    # Clean up CSR
    rm -f "${filename}.csr"
    
    echo "  -> ${filename}-cert.pem, ${filename}-key.pem"
done

echo ""
echo "=== Certificate Generation Complete ==="
echo ""

# 4. Verify all certificates
echo "=== Verifying Certificates ==="
echo ""

echo "Verifying CA certificate..."
openssl x509 -in ca-cert.pem -noout -subject -issuer
echo ""

echo "Verifying Directory Server certificate..."
openssl verify -CAfile ca-cert.pem Directory_Server-cert.pem
openssl x509 -in Directory_Server-cert.pem -noout -subject
echo ""

echo "Verifying Chat Room certificates..."
for room in "${chat_rooms[@]}"; do
    filename=$(echo "$room" | tr ' ' '_')
    echo "Checking: $room"
    openssl verify -CAfile ca-cert.pem "${filename}-cert.pem"
    openssl x509 -in "${filename}-cert.pem" -noout -subject
done

echo ""
echo "=== All certificates verified successfully ==="
echo ""

# Clean up serial file
rm -f ca-cert.srl

# List all generated files
echo "=== Generated Files ==="
echo "CA Files:"
echo "  - ca-cert.pem (CA Certificate)"
echo "  - ca-key.pem (CA Private Key)"
echo ""
echo "Directory Server Files:"
echo "  - Directory_Server-cert.pem"
echo "  - Directory_Server-key.pem"
echo ""
echo "Chat Room Files:"
for room in "${chat_rooms[@]}"; do
    filename=$(echo "$room" | tr ' ' '_')
    echo "  - ${filename}-cert.pem"
    echo "  - ${filename}-key.pem"
done
echo ""
echo "Total: 1 CA + 1 Directory Server + 5 Chat Rooms = 7 certificate pairs"
echo ""
echo "=== Certificate generation script completed successfully ==="
