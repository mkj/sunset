#!/bin/bash

# Set remote server details
REMOTE_HOST="192.168.69.2"
REMOTE_USER="any"

# Define test files
FILES=("A_random" "B_random" "D_random" "E_random" "F_random" "G_random")

# Generate random data files
echo "Generating random data files..."
dd if=/dev/random bs=512 count=1 of=./512B_random 2>/dev/null

# Generating copies of the test file
echo "Creating copies for each test file..."
for file in "${FILES[@]}"; do
    cp ./512B_random "./${file}"
    echo "Created: ${file}"
done
ls

echo "Uploading files to ${REMOTE_USER}@${REMOTE_HOST}..."

# Upload all files
sftp -vvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR ${REMOTE_USER}@${REMOTE_HOST}  << EOF
$(printf 'put ./%s\n' "${FILES[@]}")
ls -lh
bye
EOF

echo "Cleaning up local files..."
rm -f -r ./*_random ./out/*_random

