#!/bin/bash

# Find all lines containing SFTP... OR Output Consumer...
cat $1 | \
grep -E 'SFTP <---- received: \[|Output Consumer: Bytes written \[' | \
sed 's/.*received: /c / ; s/.*written /s /'  > ${1}.txrx
# Extract received lines. Remove brackets, spaces,
# and split by comma into new lines. Finally remove empty lines.

# RX
cat $1 | \
grep -E 'SFTP <---- received: \[' | \
sed 's/.*received: //' | \
sed 's/\[//; s/\]/,/' | \
tr -d ' ' |tr ',' '\n'| \
grep -v '^$' > ${1}.rx

# TX
cat $1 | \
grep -E 'Output Consumer: Bytes written \[' | \
sed 's/.*written //' | \
sed 's/\[//; s/\]/,/' | \
tr -d ' ' |tr ',' '\n'| \
grep -v '^$' > ${1}.tx