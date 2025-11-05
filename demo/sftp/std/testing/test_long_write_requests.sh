#!/bin/bash

# Set remote server details
REMOTE_HOST="192.168.69.2"
REMOTE_USER="any"

# Define test files
FILES=("100MB_random")

# Generate random data files
echo "Generating random data files..."
dd if=/dev/random bs=1048576 count=100 of=./100MB_random 2>/dev/null
# dd if=/dev/random bs=1048576 count=1024 of=./1024MB_random 2>/dev/null

echo "Uploading files to ${REMOTE_USER}@${REMOTE_HOST}..."

# Upload all files
sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR ${REMOTE_USER}@${REMOTE_HOST} -vvv << EOF
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
rm -f -r ./*_random ./out/*_random

echo "Upload test completed."