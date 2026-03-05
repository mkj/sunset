#!/bin/bash
# Tests the GET command with a single file of 100MB
# It tests if the downloaded file is the same as the original one (diff)
# Run it from the project root directory or testing folder

BASE_DIR=$(pwd)

if [ -f "Cargo.toml" ]; then
    REMOTE_DIR=$BASE_DIR"/demo/sftp/std/testing/out"
elif [[ "$BASE_DIR" == *"/testing"* ]]; then
    REMOTE_DIR=$BASE_DIR"/out"
else
    echo "Please run this script from the project root or from the testing folder"
    exit 1
fi

echo "Testing Single long GETs..."

echo "Cleaning up previous run files"
rm -f -r $BASE_DIR/*_random $REMOTE_DIR/*_random


# Set remote server details
REMOTE_HOST="192.168.69.2"
REMOTE_USER="any"



# Generate random data files
echo "Generating random data files..."
# Define test files
FILES=("100MB_random")

echo "Generating random data files..."
dd if=/dev/random bs=1048576 count=100 of=$REMOTE_DIR/100MB_random 2>/dev/null


echo "Downloading files..."
sftp -vvvvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=DEBUG ${REMOTE_USER}@${REMOTE_HOST} 2>&1 << EOF
$(printf 'get ./%s\n' "${FILES[@]}")
bye
EOF

echo "DOWNLOAD Test Results:"
echo "============="
# Test each file
for file in "${FILES[@]}"; do
    if diff "$BASE_DIR/${file}" "$REMOTE_DIR/${file}" >/dev/null 2>&1; then
        echo "Download PASS: ${file}. Cleaning it"
        rm -f -r "$BASE_DIR/${file}" "$REMOTE_DIR/${file}"        
    else
        echo "Download FAIL: Keeping downloaded and remote files for inspection
            ${BASE_DIR}/${file} and ${REMOTE_DIR}/${file}"
    fi
done
