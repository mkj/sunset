#!/bin/bash
# Writes some files in the remote server folder and list them with the LS command
# Run it from the project root directory or testing folder
# This script requires expect tool

if ! command -v expect >/dev/null 2>&1; then
    echo "Error: 'expect' is not installed or not in PATH."
    echo "Please install it and run this test again."
    exit 1
fi

BASE_DIR=$(pwd)

if [ -f "Cargo.toml" ]; then
    REMOTE_DIR=$BASE_DIR"/demo/sftp/std/testing/out"
elif [[ "$BASE_DIR" == *"/testing"* ]]; then
    REMOTE_DIR=$BASE_DIR"/out"
else
    echo "Please run this script from the project root or from the testing folder"
    exit 1
fi

# Set remote server details
REMOTE_HOST="192.168.69.2"
REMOTE_USER="any"

# Define test files
FILES=("A_random" "B_random" "D_random" "E_random" "F_random" "G_random")

# Generate random data files
echo "Generating random data files..."
dd if=/dev/random bs=512 count=1 of=$REMOTE_DIR/512B_random 2>/dev/null

# Generating copies of the test file
echo "Creating copies for each test file..."
for file in "${FILES[@]}"; do
    cp $REMOTE_DIR/512B_random "$REMOTE_DIR/${file}"
done

rm $REMOTE_DIR/512B_random

echo "Files created in remote folder ($REMOTE_DIR):"
echo "============="
ls -l $REMOTE_DIR
echo ""

# Using expect to automate the sftp session and list the files in the remote folder
# Comparing them to the expected files list


echo "Checking that the filenames are present"
echo "=============="


FILES_STR="${FILES[*]}"
export FILES_STR REMOTE_HOST REMOTE_USER
expect << 'EOF'
set timeout 20

spawn sftp -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $env(REMOTE_USER)@$env(REMOTE_HOST)

# Wait for sftp> prompt
expect {
    -re {(?m)^sftp> ?$} {}
    -re {(?i)password:} {
        puts "ERROR: password prompt received"
        exit 1
    }
    -re {.+\n} { exp_continue }
    timeout {
        puts "ERROR: did not receive sftp prompt"
        exit 1
    }
    eof {
        puts "ERROR: sftp terminated before showing prompt"
        exit 1
    }
}

send -- "ls -1\r"
expect {
    -re {(?ms)(.*)\r?\nsftp> ?$} {
        set ls_output $expect_out(1,string)
    }
    timeout {
        puts "ERROR: did not receive prompt after ls"
        exit 1
    }
    eof {
        puts "ERROR: sftp terminated after ls"
        exit 1
    }
}
# Normalize CRLF -> LF for reliable matching
regsub -all {\r} $ls_output "" ls_output

set expected_files [split $env(FILES_STR) " "]
foreach f $expected_files {
    if {![regexp -line -- "^$f$" $ls_output]} {
        puts "ERROR: missing file: $f"
        exit 1
    }
}
send -- "bye\r"
expect eof
EOF
EXPECT_RESULT=$?

echo "Cleaning up local files..."
rm -f -r $REMOTE_DIR/*_random 

if [ "$EXPECT_RESULT" -ne 0 ]; then
    echo "SFTP connection test failed"
    exit 1
else
    echo "SFTP connection test passed: all expected files are present"
    
    exit 0
fi


