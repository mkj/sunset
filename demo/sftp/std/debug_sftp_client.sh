#!/bin/bash
# This sftp options are meant to help debugging and do not store any host key or known hosts information.
# That is not a good practice in real life, as it can lead to security issues, but it is useful for debugging purposes.

sftp -vvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR any@192.168.69.2