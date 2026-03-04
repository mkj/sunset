#!/bin/bash

echo "Testing Stats..."

# Set remote server details
REMOTE_HOST="192.168.69.2"
REMOTE_USER="any"

# Define test files
FILES=("512B_random")

# Generate random data files
echo "Generating random data files..."
dd if=/dev/random bs=512 count=1 of=./512B_random 2>/dev/null

echo "Uploading files to ${REMOTE_USER}@${REMOTE_HOST}..."

# Upload all files
sftp -vvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=DEBUG ${REMOTE_USER}@${REMOTE_HOST}  << EOF
$(printf 'put ./%s\n' "${FILES[@]}")
$(printf 'ls -lh ./%s\n' "${FILES[@]}")

bye
EOF

echo "Cleaning up local files..."
rm -f -r ./*_random ./out/*_random
