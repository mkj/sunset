#!/bin/bash

echo "Launching latest build demo with log and strace..."

cargo build -p sunset-demo-sftp-std

if [ $? -ne 0 ]; then
    echo "Failed to build sunset-demo-sftp-std. Aborting"
    return 1
fi

# Create logs directory if it doesn't exist
LOG_DIR="$PWD/logs"
mkdir -p "$LOG_DIR"

CURRENT_DIR=$(pwd)
cd ../../../../
RUST_LOG_FILE="$LOG_DIR/log_demo_get_single.log"  RUST_LOG="trace" strace-opt $LOG_DIR target/debug/sunset-demo-sftp-std &

echo "Sleeping for 3 seconds to let the server start..."
sleep 3 

cd "$CURRENT_DIR"
echo "Testing GET long file..."

echo "Cleaning up previous run files"
rm -f -r ./*_random ./out/*_random

echo "Logging test_get_long... to $LOG_DIR"
./test_get_long.sh > $LOG_DIR/log_get_long.log 2>&1
echo "Finished logging GET long file."