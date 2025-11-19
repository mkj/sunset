#!/bin/bash

echo "Testing Multiple GETs..."

# Set remote server details
REMOTE_HOST="192.168.69.2"
REMOTE_USER="any"

# Define test files
FILES=("512B_random" "16kB_random" "64kB_random" "65kB_random" "2048kB_random")

# Generate random data files
echo "Generating random data files..."
dd if=/dev/random bs=512 count=1 of=./512B_random 2>/dev/null
dd if=/dev/random bs=1024 count=16 of=./16kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=64 of=./64kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=65 of=./65kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=256 of=./256kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=1024 of=./1024kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=2048 of=./2048kB_random 2>/dev/null
echo "Uploading files to ${REMOTE_USER}@${REMOTE_HOST}..."

# Upload the files
sftp  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR ${REMOTE_USER}@${REMOTE_HOST}  << EOF
$(printf 'put ./%s\n' "${FILES[@]}")

bye
EOF

echo "UPLOAD Test Results:"
echo "============="
# Test each file
for file in "${FILES[@]}"; do
    if diff "./${file}" "./out/${file}" >/dev/null 2>&1; then
        echo "Upload PASS: ${file}"
    else
        echo "Upload FAIL: ${file}"
    fi
done

echo "Cleaning up original files..."
rm -f -r ./*_random

# Download the files
sftp -vvvvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR ${REMOTE_USER}@${REMOTE_HOST}  << EOF
$(printf 'get ./%s\n' "${FILES[@]}")

bye
EOF

echo "DOWNLOAD Test Results:"
echo "============="
# Test each file
for file in "${FILES[@]}"; do
    if diff "./${file}" "./out/${file}" >/dev/null 2>&1; then
        echo "Download PASS: ${file}"
    else
        echo "Download FAIL: ${file}"
    fi
done


echo "Cleaning up local files..."
rm -f -r ./*_random ./out/*_random
