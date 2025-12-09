#!/bin/bash

TIME_STAMP=$(date +%Y%m%d_%H%M%S)
TEST_FILE=$1
# Used for log files naming
BASE_NAME=$(basename "$TEST_FILE" | cut -d. -f1)
START_PWD=$PWD
PROYECT_ROOT=$(dirname "$PWD")/../../..

# Check if file exist and can be executed

if [ ! -f "${TEST_FILE}" ]; then 
    echo "File ${TEST_FILE} not found"
    exit 1
fi
if [ ! -x "${TEST_FILE}" ]; then 
    echo "File ${TEST_FILE} is not executable"
    exit 2
fi

echo "debuging file: $TEST_FILE with logging and pcap"

cargo build -p sunset-demo-sftp-std
if [ $? -ne 0 ]; then
    echo "Failed to build sunset-demo-sftp-std. Aborting"
    return 1
fi

sleep 3;
clear;

# Create logs directory if it doesn't exist
LOG_DIR="$PWD/logs"
mkdir -p "$LOG_DIR"


# Starts an Tshark session to capture packets in tap0
WIRESHARK_LOG=${LOG_DIR}/${TIME_STAMP}_${BASE_NAME}.pcap
tshark -i tap0 -w ${WIRESHARK_LOG} &
TSHARK_PID=$!

# waits while tshark started writting to the file
echo "Waiting for tshark to start..."

while [ ! -s "${WIRESHARK_LOG}" ]; do
    sleep 1
done
echo "Tshark has started."

# ################################################################
# Start the sunset-demo-sftp-std with strace
# ################################################################
echo "Starting sunset-demo-sftp-std"
echo "Changing directory to Project root: ${PROYECT_ROOT}"
cd ${PROYECT_ROOT}
echo "Project root directory is: ${PWD}"
RUST_LOG_FILE="${LOG_DIR}/${TIME_STAMP}_${BASE_NAME}.log"
STRACE_LOG=${LOG_DIR}/${TIME_STAMP}_${BASE_NAME}_strace.log
STRACE_OPTIONS="-fintttCDTYyy -v"
STRACE_CMD="strace ${STRACE_OPTIONS} -o ${STRACE_LOG} -P /dev/net/tun ./target/debug/sunset-demo-sftp-std"

echo "Running strace for sunset-demo-sftp-std:"
echo "TZ=UTC ${STRACE_CMD}"
TZ=UTC ${STRACE_CMD} 2>&1 > $RUST_LOG_FILE &
STRACE_PID=$!

echo "Sleeping for 2 seconds to let the server start..."
sleep 2 

echo "Changing back to the starting directory: $START_PWD"
cd $START_PWD

echo "Cleaning up previous run files"
rm -f -r ./*_random ./out/*_random

echo "Running ${TEST_FILE}. Logging all data to ${LOG_DIR} with prefix ${TIME_STAMP}."
${TEST_FILE} | awk '{ cmd = "date -u +\"[%Y-%m-%dT%H:%M:%S.%NZ]\""; cmd | getline timestamp; print timestamp, $0; close(cmd) }' > $LOG_DIR/${TIME_STAMP}_${BASE_NAME}_client.log 2>&1 &
TEST_FILE_PID=$!

cleanup() {
    echo "Cleaning up..."
    kill -SIGTERM $TSHARK_PID
    kill -SIGTERM $STRACE_PID
    kill -SIGTERM $TEST_FILE_PID
    echo "Cleanup done."
}

trap cleanup SIGINT SIGTERM EXIT

echo "If stuck use Ctrl+C to stop the script and cleanup."
wait "$TEST_FILE_PID"

echo "Finished executing ${TEST_FILE}"

cleanup
