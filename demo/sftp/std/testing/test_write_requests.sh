#!/bin/bash

# Set remote server details
REMOTE_HOST="192.168.69.2"
REMOTE_USER="any"

# Define test files
FILES=("512B_random" "16kB_random" "64kB_random" "65kB_random" "256kB_random" "1MB_random" "2MB_random")

# Generate random data files
echo "Generating random data files..."
dd if=/dev/random bs=512 count=1 of=./512B_random 2>/dev/null
dd if=/dev/random bs=1024 count=16 of=./16kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=64 of=./64kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=65 of=./65kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=256 of=./256kB_random 2>/dev/null
dd if=/dev/random bs=1048576 count=1 of=./1MB_random 2>/dev/null
dd if=/dev/random bs=1048576 count=2 of=./2MB_random 2>/dev/null

echo "Uploading files to ${REMOTE_USER}@${REMOTE_HOST}..."

# Upload all files
sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR ${REMOTE_USER}@${REMOTE_HOST} << EOF
$(printf 'put ./%s\n' "${FILES[@]}")
bye
EOF

echo "Test Results:"
echo "============="

# Test each file
for file in "${FILES[@]}"; do
    if diff "./${file}" "./out/${file}" >/dev/null 2>&1; then
        echo "PASS: ${file}"
    else
        echo "FAIL: ${file}"
    fi
done

echo "Cleaning up local files..."
rm -f ./*_random ./out/*_random

echo "Upload test completed."