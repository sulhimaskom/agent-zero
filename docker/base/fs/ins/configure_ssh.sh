#!/bin/bash
set -e

# Set up SSH securely
# SECURITY FIX: Disable root login - use key-based authentication only
mkdir -p /var/run/sshd

# Configure SSH securely - disable root login
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Additional security hardening
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config