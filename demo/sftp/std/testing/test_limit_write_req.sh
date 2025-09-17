#!/bin/bash

# Set remote server details
REMOTE_HOST="192.168.69.2"
REMOTE_USER="any"

# Generate random data files
echo "Generating random data files..."

dd if=/dev/random bs=1024 count=65 of=./TwoWriteRequests_random 2>/dev/null # Fails


echo "Uploading files to ${REMOTE_USER}@${REMOTE_HOST}..."
echo "Test Results:"
echo "============="

sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR ${REMOTE_USER}@${REMOTE_HOST} << EOF
put ./TwoWriteRequests_random
bye
EOF

diff ./TwoWriteRequests_random ./out/TwoWriteRequests_random
if [ $? -eq 0 ]; then
    echo "PASS"
else
    echo "FAIL"
fi

echo "Cleaning up local files..."
rm -f ./*_random
rm -f ./out/*_random

echo "Upload test completed."