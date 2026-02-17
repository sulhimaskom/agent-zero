#!/bin/bash
set -e

# Set up SSH securely
# SECURITY: Disable root login - use key-based authentication only
mkdir -p /var/run/sshd

# Disable root login for security
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config