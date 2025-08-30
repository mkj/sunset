#!/bin/sh
# This script generates the tap device that the demo will bind the network stack
# usage `sudo ./tap.sh`

ip tuntap add name tap0 mode tap user $SUDO_USER group $SUDO_USER
ip addr add 192.168.69.100/24 dev tap0
ip link set tap0 up
