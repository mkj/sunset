#!/bin/bash

# Set remote server details
REMOTE_HOST="192.168.69.2"
REMOTE_USER="any"

# Generate random data files
echo "Generating random data files..."
dd if=/dev/random bs=128 count=1 of=./128B_random 2>/dev/null
dd if=/dev/random bs=512 count=1 of=./512B_random 2>/dev/null
dd if=/dev/random bs=1024 count=2 of=./2kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=4 of=./4kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=16 of=./16kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=64 of=./64kB_random 2>/dev/null # OK
dd if=/dev/random bs=1024 count=65 of=./MaxMaybe_random 2>/dev/null # Fails
dd if=/dev/random bs=1024 count=1024 of=./1MB_random 2>/dev/null


echo "Uploading files to ${REMOTE_USER}@${REMOTE_HOST}..."
echo "Test Results:"
echo "============="

# put ./128B_random
# put ./512B_random
# put ./2kB_random
# put ./4kB_random
# put ./16kB_random
# put ./1MB_random
# put ./MaxMaybe_random
sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR ${REMOTE_USER}@${REMOTE_HOST} << EOF
put ./64kB_random
bye
EOF


if [ $? -eq 0 ]; then
    echo "PASS"
else
    echo "FAIL"
fi

echo "Cleaning up local files..."
rm -f ./*_random

echo "Upload test completed."