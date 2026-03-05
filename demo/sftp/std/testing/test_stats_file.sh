#!/bin/bash
# This test checks the stats of a single file
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

echo "Testing Stats..."

# Set remote server details
REMOTE_HOST="192.168.69.2"
REMOTE_USER="any"

# Define test files
FILES=("512B_random")

# Generate random data files
echo "Generating random data files..."
dd if=/dev/random bs=512 count=1 of=$REMOTE_DIR/512B_random 2>/dev/null

# # List files
# sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${REMOTE_USER}@${REMOTE_HOST}  << EOF
# $(printf 'ls -l %s\n' "${FILES[@]} | awk '{print $1, $9}'")
# bye
# EOF

FILES_STR="${FILES[*]}"

export REMOTE_HOST REMOTE_USER FILES_STR
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

send -- "ls -ln\r"
expect {
    -re {(?ms)(.*)\r?\nsftp> ?$} {
        set ls_output $expect_out(0,string)
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

# Normalize CRLF -> LF
regsub -all {\r} $ls_output "" ls_output

# Hardcoded expected values. If 
set expected_name "512B_random"
set expected_perm "-rw-rw-r--"
set expected_uid  "1000"
set expected_gid  "1000"
set expected_size "512"

set found 0
foreach line [split $ls_output "\n"] {
    set line [string trim $line]
    if {$line eq ""} { continue }
    if {[string match "ls -ln*" $line]} { continue }   ;# echoed command
    if {[string match "sftp>*" $line]} { continue }    ;# prompt
    if {[string match "total *" $line]} { continue }   ;# ls header

    puts "Good candidate: <$line>"

    # Split into non-space fields:
    # perms links uid gid size month day time-or-year name
    set fields [regexp -all -inline {\S+} $line]
    if {[llength $fields] < 9} {
        puts "Skip: not enough fields: <$line>"
        continue
    }

    set perm [lindex $fields 0]
    set uid  [lindex $fields 2]
    set gid  [lindex $fields 3]
    set size [lindex $fields 4]
    set name [lindex $fields end]

    puts "Parsed: perm=$perm uid=$uid gid=$gid size=$size name=$name"

    if {$name ne $expected_name} {
        puts "Skip: different filename: <$line>"
        continue
    }

    set found 1

    if {$perm ne $expected_perm || $uid ne $expected_uid || $gid ne $expected_gid || $size ne $expected_size} {
        puts "ERROR: stat mismatch for $expected_name"
        puts "  expected: perm=$expected_perm uid=$expected_uid gid=$expected_gid size=$expected_size"
        puts "  actual:   perm=$perm uid=$uid gid=$gid size=$size"
        exit 1
    }
}

if {!$found} {
    puts "ERROR: file $expected_name not found in ls output"
    exit 1
} else {
    puts "Stats test passed: file $expected_name has expected permissions, ownership and size"
    exit 0
}

send -- "bye\r"
expect eof
EOF
EXPECT_RESULT=$?

if [ "$EXPECT_RESULT" -ne 0 ]; then
    echo "SFTP stats test failed"
    exit 1
else
    echo "SFTP stats test passed"
    exit 0
fi

echo "Cleaning up local files..."
rm -f -r $REMOTE_DIR/*_random