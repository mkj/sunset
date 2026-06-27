#!/bin/bash
# Test PUT a long file of 100MB
# It tests if the uploaded file is the same as the original one (diff)
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

# Cleaning the remote directory
rm -f -r $REMOTE_DIR/*

# Set remote server details
REMOTE_HOST="192.168.69.2"
REMOTE_USER="any"

# Define test files
FILES=("100MB_random")

# Generate random data files
echo "Generating random data files..."
dd if=/dev/random bs=1048576 count=100 of=$BASE_DIR/100MB_random 2>/dev/null


echo "Uploading files to ${REMOTE_USER}@${REMOTE_HOST}..."

# Upload all files
sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${REMOTE_USER}@${REMOTE_HOST} << EOF
$(printf "put $BASE_DIR/%s\n" "${FILES[@]}")
bye
EOF

echo "Test Results:"
echo "============="

# Test each file
DIFF_RESULT=0
for file in "${FILES[@]}"; do
    if diff "$BASE_DIR/${file}" "$REMOTE_DIR/${file}" >/dev/null 2>&1; then
        echo "PASS: ${file}"
        rm -f -r "$BASE_DIR"/${file} "$REMOTE_DIR"/${file}
    else
        ((DIFF_RESULT++))
        echo "FAIL: ${file}"
    fi
done

if [ "$DIFF_RESULT" -ne 0 ]; then
    echo "$DIFF_RESULT files failed: Keeping file(s) for inspection"
    exit "$DIFF_RESULT"
else
    echo "Upload test Passed."
    exit 0
fi

