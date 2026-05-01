#!/bin/bash

# Find all lines containing SFTP... OR Output Consumer... OR Output Producer...
# and reformat them into a simpler form for further processing.


cat <<EOF > ${1}.txrx
Extracting communications from sunset-demo-sftp-std log file: $1
Extract of RX (c: Client), TX (s: server), And internal TX (p: pipe producer)
------------------------------------------------
EOF

cat $1 | \
grep -E 'SFTP <---- received: \[|Output Consumer: Bytes written \[|Output Producer: Sending buffer \[' | \
sed 's/.*received: /c / ; s/.*written /s / ; s/.*Output Producer: Sending buffer /p /'  >> ${1}.txrx


# Extract received lines. Remove brackets, spaces,
# and split by comma into new lines. Finally remove empty lines.

# RX
cat $1 | \
grep -E 'SFTP <---- received: \[' | \
sed 's/.*received: //' | \
sed 's/\[//; s/\]/,/' | \
tr -d ' ' |tr ',' '\n'| \
grep -v '^$' > ${1}.rx

# Producer
cat $1 | \
grep -E 'Output Producer: Sending buffer \[' | \
sed 's/.*buffer //' | \
sed 's/\[//; s/\]/,/' | \
tr -d ' ' |tr ',' '\n'| \
grep -v '^$' > ${1}.txp

# TX
cat $1 | \
grep -E 'Output Consumer: Bytes written \[' | \
sed 's/.*written //' | \
sed 's/\[//; s/\]/,/' | \
tr -d ' ' |tr ',' '\n'| \
grep -v '^$' > ${1}.tx