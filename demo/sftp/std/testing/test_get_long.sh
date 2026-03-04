#!/bin/bash

echo "Testing Single long GETs..."

echo "Cleaning up previous run files"
rm -f -r ./*_random ./out/*_random


# Set remote server details
REMOTE_HOST="192.168.69.2"
REMOTE_USER="any"



# Generate random data files
echo "Generating random data files..."
# Define test files
FILES=("100MB_random")

echo "Generating random data files..."
dd if=/dev/random bs=1048576 count=100 of=./100MB_random 2>/dev/null
echo "Uploading files to ${REMOTE_USER}@${REMOTE_HOST}..."

echo "Moving to the server folder..."
for file in "${FILES[@]}"; do
    mv "./${file}" "./out/${file}"
done

echo "Downloading files..."
sftp -vvvvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=DEBUG ${REMOTE_USER}@${REMOTE_HOST} 2>&1 << EOF
$(printf 'get ./%s\n' "${FILES[@]}")
bye
EOF

echo "DOWNLOAD Test Results:"
echo "============="
# Test each file
for file in "${FILES[@]}"; do
    if diff "./${file}" "./out/${file}" >/dev/null 2>&1; then
        echo "Download PASS: ${file}. Cleaning it"
        rm -f -r ./${file} ./out/${file}        
    else
        echo "Download FAIL: ${file}". Keeping for inspection
    fi
done
