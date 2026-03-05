#!/bin/bash
# Test PUT a small files onto the server
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
FILES=("512B_random" "16kB_random" "64kB_random" "65kB_random" "256kB_random" "1024kB_random" "2048kB_random")

# Generate random data files
echo "Generating random data files..."
dd if=/dev/random bs=512 count=1 of=$BASE_DIR/512B_random 2>/dev/null
dd if=/dev/random bs=1024 count=16 of=$BASE_DIR/16kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=64 of=$BASE_DIR/64kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=65 of=$BASE_DIR/65kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=256 of=$BASE_DIR/256kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=1024 of=$BASE_DIR/1024kB_random 2>/dev/null
dd if=/dev/random bs=1024 count=2048 of=$BASE_DIR/2048kB_random 2>/dev/null


echo "Uploading files to ${REMOTE_USER}@${REMOTE_HOST}..."

# Upload all files
sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${REMOTE_USER}@${REMOTE_HOST} -vvv << EOF
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

