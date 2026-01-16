#!/bin/bash

sftp -vvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR any@192.168.69.2